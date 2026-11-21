"""Ask the local network what it offers over multicast DNS (RFC 6762, DNS-SD in RFC 6763).

Queries go out from an ephemeral port, which makes them "legacy unicast"
queries (RFC 6762 section 6.7): most responders answer straight back to that
port, which works next to Bonjour or Avahi holding port 5353.

Not every answer comes back that way. Windows answers on port 5353 whatever
port the query came from, and Linux host firewalls (ufw, firewalld) drop
unicast replies to multicast queries. So everywhere but on Windows the same
questions also go out as standard queries from a socket that shares port 5353
and joins the group, and the multicast answers it hears count as well.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..models import MdnsInfo
from ..scope import is_local
from ..system import IS_WINDOWS
from . import _udp
from .dnswire import (
    AAAA,
    FLAG_RESPONSE,
    MAX_RECORDS,
    PTR,
    SRV,
    TXT,
    A,
    DnsError,
    Labels,
    Message,
    Record,
    build_query,
    display_text,
    encode_name,
    name_key,
    name_text,
    parse_message,
    read_header,
    reverse_name,
)

MDNS_GROUP = ("224.0.0.251", 5353)
MDNS_PORT = 5353

# Asked for directly as well as through the service list, because plenty of
# small devices never answer the _services._dns-sd._udp meta query.
COMMON_SERVICES = (
    # Computers and file sharing
    "_workstation._tcp",
    "_device-info._tcp",
    "_smb._tcp",
    "_afpovertcp._tcp",
    "_adisk._tcp",
    "_nfs._tcp",
    "_ssh._tcp",
    "_sftp-ssh._tcp",
    "_rfb._tcp",
    # Apple devices
    "_airplay._tcp",
    "_raop._tcp",
    "_companion-link._tcp",
    "_apple-mobdev2._tcp",
    "_mediaremotetv._tcp",
    "_sleep-proxy._udp",
    # Speakers, TVs and streaming
    "_googlecast._tcp",
    "_spotify-connect._tcp",
    "_sonos._tcp",
    "_amzn-wplay._tcp",
    "_androidtvremote2._tcp",
    "_nvstream._tcp",
    "_daap._tcp",
    "_plexmediasvr._tcp",
    # Printers and scanners
    "_ipp._tcp",
    "_ipps._tcp",
    "_printer._tcp",
    "_pdl-datastream._tcp",
    "_uscan._tcp",
    "_uscans._tcp",
    "_scanner._tcp",
    # Smart home
    "_hap._tcp",
    "_hap._udp",
    "_homekit._tcp",
    "_matter._tcp",
    "_matterc._udp",
    "_meshcop._udp",
    "_hue._tcp",
    "_esphomelib._tcp",
    "_home-assistant._tcp",
    "_miio._udp",
    "_elg._tcp",
    "_shelly._tcp",
    "_wled._tcp",
    "_nanoleafapi._tcp",
    "_mqtt._tcp",
    # Cameras and web interfaces
    "_rtsp._tcp",
    "_axis-video._tcp",
    "_http._tcp",
    "_https._tcp",
)

# Responders cap legacy unicast replies at 512 bytes (Avahi does) and cut the
# rest, so each packet only asks a few questions.
QUESTIONS_PER_PACKET = 3
SPACING = 0.01
UNICAST_SPACING = 0.003
# Share of the time after which the service types learned so far get asked.
ROUND_TWO_AT = 0.4

MAX_HOSTS = 256
MAX_SERVICES_PER_HOST = 64
MAX_INSTANCES = 1024
MAX_NAMES = 1024  # A and AAAA record owners
MAX_ADDRESSES_PER_NAME = 8
MAX_SENDERS = 4  # per instance
MAX_LEARNED = 128
MAX_ROUND_TWO = 32

# Replies are parsed on the event loop, so a flood must not keep it busy:
# per socket, at most this many replies, and this many from any one address.
MAX_REPLIES = 1024
MAX_REPLIES_PER_SENDER = 32
# Questions and records read over all replies to one browse or reverse lookup.
RECORD_BUDGET = 16384
# One sender may use up at most this fraction of the budget.
SENDER_SHARE = 8

# Windows Firewall drops inbound multicast for programs it has not been told
# about, and binding port 5353 there can bring up a firewall prompt.
LISTEN_ON_5353 = not IS_WINDOWS

_META = ("_services", "_dns-sd", "_udp", "local")
_SERVICE_LABEL = re.compile(r"_[a-z0-9][a-z0-9-]{0,62}")
_PROTOCOLS = ("_tcp", "_udp")


def _usable(address: str) -> bool:
    """A private IPv4 address that is not loopback."""
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return False
    return is_local(ip) and not ip.is_loopback


def _service_type(labels: Labels) -> str | None:
    """ "_airplay._tcp" for a name ending in _airplay._tcp.local, else None."""
    if len(labels) < 3:
        return None
    service, protocol, domain = name_key(labels[-3:])
    if domain != "local" or protocol not in _PROTOCOLS:
        return None
    if not _SERVICE_LABEL.fullmatch(service):
        return None
    return f"{service}.{protocol}"


def _split_instance(labels: Labels) -> tuple[str, str] | None:
    """(instance name, service type) for "Living Room._airplay._tcp.local"."""
    if len(labels) < 4 or (len(labels) == len(_META) and name_key(labels) == _META):
        return None
    service = _service_type(labels)
    if service is None:
        return None
    # Some responders send dots in instance names as label separators.
    return ".".join(labels[:-3]), service


def _questions(services: Iterable[str]) -> list[tuple[Labels, int]]:
    return [((*service.split("."), "local"), PTR) for service in services]


def _packets(
    questions: list[tuple[Labels, int]], query_id: int, address: tuple[str, int]
) -> list[tuple[bytes, tuple[str, int]]]:
    usable = []
    for name, qtype in questions:
        try:
            encode_name(name)
        except DnsError:
            continue  # a name we decoded but cannot send back, like a mangled label
        usable.append((name, qtype))
    return [
        (build_query(usable[i : i + QUESTIONS_PER_PACKET], query_id=query_id), address)
        for i in range(0, len(usable), QUESTIONS_PER_PACKET)
    ]


class _Answers:
    """Parses answers to one query id, within a record budget shared out per sender."""

    def __init__(self, query_id: int) -> None:
        self.query_id = query_id
        self.budget = RECORD_BUDGET
        self.spent: dict[str, int] = {}

    def read(self, data: bytes, sender: str) -> Message | None:
        try:
            msg_id, flags, entries = read_header(data)
        except DnsError:
            return None
        opcode = (flags >> 11) & 0xF
        # Some small responders leave the id at zero instead of echoing ours.
        if not flags & FLAG_RESPONSE or opcode or msg_id not in (self.query_id, 0):
            return None
        # Charged before parsing, so malformed messages use it up as well. A
        # record takes at least 11 bytes, so a bare header claiming thousands
        # of them only pays for what it could really hold, and no single
        # sender gets more than its share.
        cost = min(entries, MAX_RECORDS, max(0, len(data) - 12) // 11)
        spent = self.spent.get(sender, 0)
        if self.budget < cost or spent + cost > RECORD_BUDGET // SENDER_SHARE:
            return None
        self.budget -= cost
        self.spent[sender] = spent + cost
        try:
            return parse_message(data)
        except DnsError:
            return None


@dataclass(slots=True)
class _Instance:
    labels: Labels  # the full name as sent, for asking about it again
    service: str
    name: str
    senders: list[str] = field(default_factory=list)
    target: Labels | None = None  # SRV target host
    txt: dict[str, str] | None = None


@dataclass(slots=True)
class _Host:
    labels: Labels
    # Private IPv4 only, so empty for a host known only from AAAA records.
    addresses: list[str] = field(default_factory=list)


class _Findings:
    """What a set of replies says, before it is pinned to addresses."""

    def __init__(self, query_id: int) -> None:
        self.answers = _Answers(query_id)
        self.instances: dict[Labels, _Instance] = {}
        self.hosts: dict[Labels, _Host] = {}
        self.listed: dict[str, list[str]] = {}  # sender -> types it gave for the meta query
        self.learned: dict[str, None] = {}

    def add(self, data: bytes, sender: str) -> None:
        if not _usable(sender):
            return
        message = self.answers.read(data, sender)
        if message is None:
            return
        for record in message.records:
            if record.rtype == A:
                self._address(record)
            elif record.rtype == AAAA:
                self._host(record.name)
            elif record.rtype == PTR:
                self._pointer(record, sender)
            elif record.rtype == SRV:
                instance = self._instance(record.name, sender)
                _, _, _, target = record.data
                # A target of "." means the service is not offered after all.
                if instance is not None and instance.target is None and target:
                    instance.target = target
            elif record.rtype == TXT:
                instance = self._instance(record.name, sender)
                if instance is not None and instance.txt is None:
                    instance.txt = {
                        display_text(key): display_text(value) for key, value in record.data.items()
                    }

    def _address(self, record: Record) -> None:
        address = record.data
        if not _usable(address):
            return
        host = self._host(record.name)
        if (
            host is not None
            and address not in host.addresses
            and len(host.addresses) < MAX_ADDRESSES_PER_NAME
        ):
            host.addresses.append(address)

    def _host(self, labels: Labels) -> _Host | None:
        key = name_key(labels)
        host = self.hosts.get(key)
        if host is None:
            if len(self.hosts) >= MAX_NAMES or not key:
                return None
            host = self.hosts[key] = _Host(labels)
        return host

    def _pointer(self, record: Record, sender: str) -> None:
        # The meta query and browse answers have three to five labels.
        if not 3 <= len(record.name) <= 5:
            return
        owner = name_key(record.name)
        target = record.data
        if owner == _META:
            service = _service_type(target) if len(target) == 3 else None
            if service is None:
                return
            if len(self.learned) < MAX_LEARNED:
                self.learned.setdefault(service)
            listed = self.listed.get(sender)
            if listed is None:
                if len(self.listed) >= MAX_HOSTS:
                    return
                listed = self.listed[sender] = []
            if service not in listed and len(listed) < MAX_SERVICES_PER_HOST:
                listed.append(service)
            return
        # A browse answer lives under the service type or one of its subtypes
        # (_printer._sub._http._tcp.local).
        if not (len(owner) == 3 or (len(owner) == 5 and owner[1] == "_sub")):
            return
        parts = _split_instance(target)
        if parts is not None and parts[1] == _service_type(owner):
            self._instance(target, sender)

    def _instance(self, labels: Labels, sender: str) -> _Instance | None:
        if _service_type(labels) is None:
            return None
        key = name_key(labels)
        instance = self.instances.get(key)
        if instance is None:
            parts = _split_instance(labels)
            if parts is None or len(self.instances) >= MAX_INSTANCES:
                return None
            name, service = parts
            instance = self.instances[key] = _Instance(labels, service, display_text(name))
        if sender not in instance.senders and len(instance.senders) < MAX_SENDERS:
            instance.senders.append(sender)
        return instance

    def follow_up(self, asked: set[str]) -> list[tuple[Labels, int]]:
        """Questions worth a second round: new service types, half-known instances."""
        questions = _questions(service for service in self.learned if service not in asked)
        for instance in self.instances.values():
            if instance.target is None:
                questions.append((instance.labels, SRV))
            if instance.txt is None:
                questions.append((instance.labels, TXT))
        return questions[:MAX_ROUND_TWO]

    def results(self) -> dict[str, MdnsInfo]:
        found: dict[str, MdnsInfo] = {}

        def entry(ip: str) -> MdnsInfo | None:
            info = found.get(ip)
            if info is None and len(found) < MAX_HOSTS:
                info = found[ip] = MdnsInfo()
            return info

        def offer(info: MdnsInfo, service: str) -> bool:
            if service in info.services:
                return True
            if len(info.services) >= MAX_SERVICES_PER_HOST:
                return False
            info.services.add(service)
            return True

        for instance in self.instances.values():
            hostname = None
            addresses = instance.senders
            if instance.target is not None:
                host = self.hosts.get(name_key(instance.target))
                if host is not None:
                    if not host.addresses:
                        # Known by IPv6 addresses only, so not the sender's to
                        # claim: a Thread device behind its border router, say.
                        continue
                    addresses = host.addresses
                    hostname = name_text(instance.target)
            # With nothing known about the target, credit whoever sent the
            # instance, but not with the target's name: the sender may be a
            # proxy answering for someone else.
            for ip in addresses:
                info = entry(ip)
                if info is None or not offer(info, instance.service):
                    continue
                if hostname and info.hostname is None:
                    info.hostname = hostname
                if instance.service not in info.instances:
                    info.instances[instance.service] = instance.name
                    if instance.txt is not None:
                        info.txt[instance.service] = dict(instance.txt)

        for sender, services in self.listed.items():
            info = entry(sender)
            if info is not None:
                for service in services:
                    offer(info, service)

        for host in self.hosts.values():
            for ip in host.addresses:
                info = entry(ip)
                if info is not None and info.hostname is None:
                    info.hostname = name_text(host.labels)
        return found


def _listen_time(deadline: float, packets: int, spacing: float) -> float:
    now = asyncio.get_running_loop().time()
    return max(0.0, deadline - now - max(packets - 1, 0) * spacing)


async def browse(local: str, *, duration: float = 2.5) -> dict[str, MdnsInfo]:
    """Browse mDNS services on the network `local` belongs to.

    Returns what each private IPv4 address announced. Takes about `duration`
    seconds. Raises OSError if no socket can be bound to `local`, or if the OS
    refused to send every one of the first queries.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + duration
    query_id = secrets.randbelow(0xFFFF) + 1
    asked = set(COMMON_SERVICES)
    questions = [(_META, PTR), *_questions(COMMON_SERVICES)]
    findings = _Findings(query_id)

    async def ask(
        packets: list[tuple[bytes, tuple[str, int]]],
        *,
        required: bool = True,
        join: tuple[str, int] | None = None,
    ) -> None:
        try:
            await _udp.exchange(
                packets,
                local=local,
                listen=_listen_time(deadline, len(packets), SPACING),
                spacing=SPACING,
                multicast_ttl=255,
                on_reply=findings.add,
                max_replies=MAX_REPLIES,
                per_sender=MAX_REPLIES_PER_SENDER,
                join=join,
            )
        except OSError:
            if required:
                raise

    tasks = [asyncio.create_task(ask(_packets(questions, query_id, MDNS_GROUP)))]
    if LISTEN_ON_5353:
        # Standard queries: id 0 and no QU bit, so the answers come by multicast.
        # Skipped quietly when the port cannot be shared.
        standard = _packets(questions, 0, MDNS_GROUP)
        tasks.append(asyncio.create_task(ask(standard, required=False, join=MDNS_GROUP)))
    try:
        await asyncio.wait(tasks[:1], timeout=duration * ROUND_TWO_AT)
        if not tasks[0].done():
            second = _packets(findings.follow_up(asked), query_id, MDNS_GROUP)
            if second and _listen_time(deadline, len(second), SPACING) > 0:
                tasks.append(asyncio.create_task(ask(second, required=False)))
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return findings.results()


async def reverse_names(local: str, ips: Iterable[str], *, duration: float = 1.0) -> dict[str, str]:
    """Ask each address for its own mDNS host name.

    Sends a PTR query for the reverse name straight to ip:5353. Returns
    ip -> name ("Living-Room.local") for the hosts that answered for themselves.
    """
    asked: dict[str, Labels] = {}
    for ip in ips:
        if ip not in asked and _usable(ip):
            asked[ip] = reverse_name(ip)
    if not asked:
        return {}
    query_id = secrets.randbelow(0xFFFF) + 1
    packets = [
        (build_query([(name, PTR)], query_id=query_id), (ip, MDNS_PORT))
        for ip, name in asked.items()
    ]
    replies = await _udp.exchange(
        packets,
        local=local,
        listen=duration,
        spacing=UNICAST_SPACING,
        max_replies=MAX_REPLIES,
        per_sender=MAX_REPLIES_PER_SENDER,
    )

    names: dict[str, str] = {}
    answers = _Answers(query_id)
    for data, sender in replies:
        if sender not in asked or sender in names:
            continue
        message = answers.read(data, sender)
        if message is None:
            continue
        expected = name_key(asked[sender])
        for record in message.records:
            if (
                record.rtype == PTR
                and record.data
                and len(record.name) == len(expected)
                and name_key(record.name) == expected
            ):
                names[sender] = name_text(record.data)
                break
    return names
