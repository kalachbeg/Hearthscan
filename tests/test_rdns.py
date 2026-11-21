import asyncio
import inspect
import sys
import types

import pytest

from hearthscan.discovery import _udp, rdns
from hearthscan.discovery.dnswire import (
    IN,
    PTR,
    Message,
    Record,
    build_message,
    parse_message,
    reverse_name,
)

LOCAL = "192.168.1.10"
ROUTER = "192.168.1.1"
SECOND = "10.0.0.53"
# Kept before any test swaps it out, so fakes can check their arguments against it.
EXCHANGE_SIGNATURE = inspect.signature(_udp.exchange)


@pytest.fixture
def posix(monkeypatch, tmp_path):
    """Pretend to be Linux with resolv.conf files under tmp_path."""
    monkeypatch.setattr(rdns, "IS_WINDOWS", False)
    files = (tmp_path / "resolv.conf", tmp_path / "systemd-resolv.conf")
    monkeypatch.setattr(rdns, "RESOLV_CONF_FILES", tuple(str(f) for f in files))
    return files


def test_parse_resolv_conf():
    text = "# made by hand\nsearch lan\nnameserver 192.168.1.1\n; old\nnameserver  10.0.0.53 # x\n"
    assert rdns.parse_resolv_conf(text) == ["192.168.1.1", "10.0.0.53"]
    assert rdns.parse_resolv_conf("nameserver\n") == []


def test_nameservers_skips_the_systemd_stub(posix):
    stub, upstream = posix
    stub.write_text("nameserver 127.0.0.53\noptions edns0\n")
    upstream.write_text(
        "nameserver 192.168.1.1\nnameserver 8.8.8.8\nnameserver fd00::1\n"
        "nameserver 10.0.0.53\nnameserver 192.168.1.254\nnameserver 192.168.1.253\n"
    )
    assert rdns.nameservers(ROUTER) == [ROUTER, SECOND, "192.168.1.254"]
    assert rdns.nameservers(None) == [ROUTER, SECOND, "192.168.1.254"]


def test_nameservers_without_files(posix):
    assert rdns.nameservers(ROUTER) == [ROUTER]
    assert rdns.nameservers(None) == []
    assert rdns.nameservers("203.0.113.1") == []
    assert rdns.nameservers("not an address") == []


def test_nameservers_survives_odd_files(posix, tmp_path):
    stub, upstream = posix
    stub.write_bytes(b"\xff\xfe nameserver \x00\x01\nnameserver 192.168.1.\xff\n")
    upstream.mkdir()
    assert rdns.nameservers("192.168.001.1") == []
    stub.write_bytes(b"nameserver 10.0.0.53\n" + b"#" * 200_000)
    assert rdns.nameservers(None) == [SECOND]


GUID = "{1B4E28BA-2FA1-11D2-883F-0016D3CCA427}"


@pytest.fixture
def registry(monkeypatch):
    """Pretend to be Windows with a registry holding `values[guid]` for each adapter."""
    values: dict[str, list[str]] = {}
    asked: list[str] = []

    def fake(guid):
        asked.append(guid)
        return values.get(guid, [])

    monkeypatch.setattr(rdns, "IS_WINDOWS", True)
    monkeypatch.setattr(rdns, "_registry_values", fake)
    return values, asked


def test_nameservers_on_windows_come_from_the_adapter(registry):
    values, _ = registry
    values[GUID] = ["", "192.168.1.2 192.168.1.1"]
    assert rdns.nameservers(ROUTER, GUID) == [ROUTER, "192.168.1.2"]
    assert rdns.nameservers(None, GUID) == ["192.168.1.2", ROUTER]


def test_nameservers_on_windows_filters_and_limits(registry):
    values, _ = registry
    values[GUID] = [
        "8.8.8.8,10.0.0.53, 127.0.0.1",
        "fd00::1 192.168.1.254 192.168.1.253 192.168.1.252",
    ]
    assert rdns.nameservers(ROUTER, GUID) == [ROUTER, SECOND, "192.168.1.254"]


def test_nameservers_on_windows_ignores_resolv_conf(posix, registry):
    stub, _ = posix
    stub.write_text("nameserver 10.0.0.53\n")
    assert rdns.nameservers(ROUTER) == [ROUTER]
    assert rdns.nameservers(None) == []


@pytest.mark.parametrize(
    "interface", [None, "", "eth0", "1B4E28BA-2FA1-11D2-883F-0016D3CCA427", GUID + "\\..", 7]
)
def test_windows_nameservers_wants_a_guid(registry, interface):
    _, asked = registry
    assert rdns.nameservers(ROUTER, interface) == [ROUTER]
    assert asked == []


def test_nameservers_elsewhere_ignore_the_registry(posix, monkeypatch):
    monkeypatch.setattr(rdns, "_registry_values", lambda guid: ["10.0.0.53"])
    assert rdns.nameservers(ROUTER, GUID) == [ROUTER]


class FakeKey:
    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_winreg(keys):
    """A stand-in for the winreg module, holding {key path: {value name: data}}."""
    module = types.SimpleNamespace(HKEY_LOCAL_MACHINE=object())

    def open_key(root, path):
        if root is not module.HKEY_LOCAL_MACHINE or path not in keys:
            raise FileNotFoundError(path)
        if keys[path] is None:
            raise PermissionError(path)
        return FakeKey(keys[path])

    def query_value(key, name):
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name], 1

    module.OpenKey = open_key
    module.QueryValueEx = query_value
    return module


def test_registry_values_reads_both_kinds(monkeypatch):
    path = rdns.TCPIP_INTERFACES + "\\" + GUID
    keys = {path: {"NameServer": ["192.168.1.2", "192.168.1.3"], "DhcpNameServer": 5}}
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg(keys))
    assert rdns._registry_values(GUID) == ["192.168.1.2", "192.168.1.3"]

    keys[path] = {"DhcpNameServer": "192.168.1.1 10.0.0.53"}
    assert rdns._registry_values(GUID) == ["192.168.1.1 10.0.0.53"]
    assert rdns._registry_values("{00000000-0000-0000-0000-000000000000}") == []

    keys[path] = None
    assert rdns._registry_values(GUID) == []


@pytest.mark.skipif(not rdns.IS_WINDOWS, reason="needs the Windows registry")
def test_registry_values_for_an_unknown_adapter():
    assert rdns._registry_values("{00000000-0000-0000-0000-000000000000}") == []
    assert rdns.windows_nameservers("{00000000-0000-0000-0000-000000000000}") == []


@pytest.mark.skipif(rdns.IS_WINDOWS, reason="winreg exists on Windows")
def test_registry_values_without_winreg():
    assert rdns._registry_values(GUID) == []


def respond(query, *hosts, rcode=0, msg_id=None, question=None):
    """A resolver's answer to `query` naming `hosts` (dotted, no trailing dot)."""
    asked = parse_message(query)
    ((name, _),) = asked.questions
    answers = [Record(name, PTR, IN, 300, tuple(host.split("."))) for host in hosts]
    message = Message(
        asked.id if msg_id is None else msg_id,
        0x8180 | rcode,
        questions=[(question or name, PTR)],
        answers=answers,
    )
    return build_message(message)


class FakeResolvers:
    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.calls = []

    async def __call__(self, packets, **kwargs):
        EXCHANGE_SIGNATURE.bind(packets, **kwargs)
        packets = list(packets)
        self.calls.append((packets, kwargs))
        replies = []
        for payload, (server, _) in packets:
            ((name, _),) = parse_message(payload).questions
            ip = ".".join(reversed(name[:4]))
            replies.extend(self.behaviour(payload, server, ip))
        # Let the second server answer first: arrival order must not matter.
        replies.sort(key=lambda r: r[1] != SECOND)
        return [*replies, (b"\x00\x01junk", ROUTER)]


def test_lookup(monkeypatch):
    def behaviour(query, server, ip):
        if server == ROUTER:
            return {
                "192.168.1.20": [(respond(query, "living-room.lan"), ROUTER)],
                "192.168.1.40": [(respond(query, "40.1.168.192.in-addr.arpa"), ROUTER)],
                "192.168.1.41": [(respond(query, "192.168.1.41"), ROUTER)],
                "192.168.1.42": [(respond(query, rcode=3), ROUTER)],
                "192.168.1.43": [(respond(query, "spoofed.lan"), "192.168.1.99")],
                "192.168.1.44": [(respond(query, "192.168.1.44.home"), ROUTER)],
                "192.168.1.45": [(respond(query, "evil\x1bname.lan"), ROUTER)],
            }.get(ip, [])
        return {
            "192.168.1.20": [(respond(query, "other-name.home"), SECOND)],
            "192.168.1.30": [
                (respond(query, "desktop-7q1.home"), SECOND),
                (respond(query, "late-duplicate.home"), SECOND),
            ],
            "192.168.1.42": [(respond(query, "wrong-id.home", msg_id=0), SECOND)],
            "192.168.1.43": [
                (
                    respond(query, "wrong-question.home", question=reverse_name("192.168.1.9")),
                    SECOND,
                )
            ],
        }.get(ip, [])

    fake = FakeResolvers(behaviour)
    monkeypatch.setattr(_udp, "exchange", fake)
    ips = [f"192.168.1.{n}" for n in (20, 30, 40, 41, 42, 43, 44, 45, 20)] + ["fe80::1", "x"]
    names = asyncio.run(rdns.lookup(LOCAL, ips, [ROUTER, SECOND, ROUTER], timeout=0.01))
    assert names == {
        "192.168.1.20": "living-room.lan",
        "192.168.1.30": "desktop-7q1.home",
        "192.168.1.45": "evil?name.lan",
    }

    ((packets, kwargs),) = fake.calls
    assert kwargs["local"] == LOCAL
    assert kwargs["listen"] == 0.01
    assert len(packets) == 8 * 2
    assert {port for _, (_, port) in packets} == {53}
    queries = [parse_message(payload) for payload, _ in packets]
    assert all(q.flags & 0x0100 for q in queries)
    assert len({q.id for q in queries}) == len(queries)
    assert 0 not in {q.id for q in queries}


def test_lookup_with_nothing_to_do(monkeypatch):
    fake = FakeResolvers(lambda *args: [])
    monkeypatch.setattr(_udp, "exchange", fake)
    assert asyncio.run(rdns.lookup(LOCAL, ["192.168.1.20"], [])) == {}
    assert asyncio.run(rdns.lookup(LOCAL, [], [ROUTER])) == {}
    assert asyncio.run(rdns.lookup(LOCAL, ["fe80::1"], ["fd00::53"])) == {}
    assert fake.calls == []
