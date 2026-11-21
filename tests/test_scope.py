import socket

import pytest

from hearthscan.scope import MAX_HOSTS, ScopeError, expand, is_local


@pytest.mark.parametrize(
    "address",
    [
        "192.168.1.20",
        "10.0.0.1",
        "172.31.255.254",
        "169.254.10.1",
        "127.0.0.1",
        "fd12:3456::1",
        "fe80::1",
        "::ffff:192.168.1.1",
    ],
)
def test_local_addresses(address):
    assert is_local(address)


@pytest.mark.parametrize(
    "address", ["8.8.8.8", "172.32.0.1", "100.64.0.1", "2001:4860::8888", "::ffff:8.8.8.8"]
)
def test_other_addresses_are_not_local(address):
    assert not is_local(address)


def test_cidr_skips_network_and_broadcast_address():
    assert expand("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


@pytest.mark.parametrize(
    "spec, expected",
    [
        ("192.168.1.7/32", ["192.168.1.7"]),
        ("192.168.1.6/31", ["192.168.1.6", "192.168.1.7"]),
        ("fd00::/126", ["fd00::1", "fd00::2", "fd00::3"]),
        ("fd00::/127", ["fd00::", "fd00::1"]),
    ],
)
def test_small_networks(spec, expected):
    assert expand(spec) == expected


def test_short_and_long_ranges():
    assert expand("192.168.1.10-12") == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
    assert expand("10.0.0.254-10.0.1.1") == ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"]
    assert expand("fd00::1-fd00::3") == ["fd00::1", "fd00::2", "fd00::3"]


def test_mixed_list_drops_duplicates():
    assert expand("192.168.1.1, 192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


def test_ipv4_mapped_targets_become_plain_ipv4():
    assert expand("::ffff:192.168.1.5, 192.168.1.5") == ["192.168.1.5"]
    assert expand("::ffff:192.168.1.0/126") == ["192.168.1.1", "192.168.1.2"]


def test_link_local_ipv6_keeps_its_zone():
    assert expand("fe80::1%eth0") == ["fe80::1%eth0"]
    assert expand("fe80::1%br-lan") == ["fe80::1%br-lan"]
    assert expand("fe80::%eth0/126") == ["fe80::1%eth0", "fe80::2%eth0", "fe80::3%eth0"]


def test_link_local_ipv6_without_zone_is_refused():
    with pytest.raises(ValueError, match="interface"):
        expand("fe80::1")


@pytest.mark.parametrize("spec", ["192.168.1", "192.168.1.010", "10.1", "0xc0a80101", "3232235777"])
def test_sloppy_numeric_addresses_are_not_guessed(spec):
    with pytest.raises(ValueError, match="not a valid IP address"):
        expand(spec)


@pytest.mark.parametrize(
    "spec", ["8.8.8.8", "8.8.8.0/24", "192.168.0.0/15", "172.31.255.250-172.32.0.5"]
)
def test_public_targets_are_refused(spec):
    with pytest.raises(ScopeError):
        expand(spec)


def test_huge_networks_are_refused():
    with pytest.raises(ScopeError, match=str(MAX_HOSTS)):
        expand("10.0.0.0/16")


@pytest.mark.parametrize(
    "spec", ["", "192.168.1.20-10", "192.168.1.10-300", "192.168.1.0/33", "fe80::1-192.168.1.1"]
)
def test_malformed_targets(spec):
    with pytest.raises(ValueError):
        expand(spec)


def test_host_names_are_resolved_and_checked(monkeypatch):
    names = {
        "nas.lan": "192.168.1.40",
        "my-printer.lan": "192.168.1.41",
        "example.com": "93.184.215.14",
    }

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host not in names:
            raise socket.gaierror("not found")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (names[host], 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert expand("nas.lan, my-printer.lan") == ["192.168.1.40", "192.168.1.41"]
    with pytest.raises(ScopeError):
        expand("example.com")
    with pytest.raises(ValueError, match="resolve"):
        expand("nowhere.lan")
