import libpry
from packet.packet import *

class uLoopback(libpry.AutoTree):
    def test_create(self):
        p = createPacket(Loopback)
        assert len(p.protostack) ==  1
        assert p.protostack.TYPE ==  "Loopback"

    def test_create_nested(self):
        p = createPacket(Loopback, IP)
        assert len(p.protostack) ==  2
        assert p["ip"]

    def test_payloads(self):
        p = createPacket(Loopback)
        expected = "supercalifragilisticexpialidocious"
        p.payload = expected
        assert p.payload ==  expected

    def test_reinitialise(self):
        p = createPacket(Loopback, IP)
        p.initialise()
        assert p["ip"]


class uEthernet(libpry.AutoTree):
    def test_create(self):
        e = createPacket(Ethernet)
        assert e["ethernet"]
        e.initialise()
        assert e["ethernet"]

    def test_create_nested(self):
        e = createPacket(Ethernet, IP)
        assert e["ip"]
        e.initialise()
        assert e["ip"]

    def test_payload(self):
        e = createPacket(Ethernet)
        expected = "foofoo"
        e.payload = expected
        e.initialise()
        assert e.payload ==  expected


class uARP(libpry.AutoTree):
    def test_create(self):
        a = createPacket(Ethernet, ARP)
        assert a["arp"]
        a.initialise()
        assert a["arp"]


class uIP(libpry.AutoTree):
    def test_create(self):
        a = createPacket(Ethernet, IP)
        assert a["ip"]
        a.initialise()
        assert a["ip"]

    def test_defaults(self):
        a = createPacket(Ethernet, IP)
        assert a["ip"].version ==  4
        assert a["ip"].ttl

    def test_create_nested(self):
        a = createPacket(Ethernet, IP, TCP)
        assert a["tcp"]
        a.initialise()
        assert a["tcp"]

    def test_payload(self):
        a = createPacket(Ethernet, IP)
        expected = "Count Frufru"
        a.payload = expected
        a.initialise()
        assert a.payload ==  expected


class uIPv6(libpry.AutoTree):
    def test_create(self):
        a = createPacket(Ethernet, IPv6)
        assert a["ipv6"]
        a.initialise()
        assert a["ipv6"]

    def test_defaults(self):
        a = createPacket(Ethernet, IPv6)
        assert a["ipv6"].version ==  6
        assert a["ipv6"].hoplimit ==  255
        assert a["ipv6"].diffservices ==  0

    def test_create_nested(self):
        a = createPacket(Ethernet, IPv6, TCP)
        assert a["ipv6"]
        a.initialise()
        assert a["tcp"]


class uTCP(libpry.AutoTree):
    def test_create(self):
        a = createPacket(Ethernet, IP, TCP)
        assert a["ip"]
        a.initialise()
        assert a["ip"]


class uUDP(libpry.AutoTree):
    def test_create(self):
        a = createPacket(Ethernet, IP, UDP)
        assert a["udp"]
        a.initialise()
        assert a["udp"]


#
# We only test one of each "flavour" of ICMP packet.
#
class uICMPDestinationUnreachable(libpry.AutoTree):
    def test_create(self):
        i = createPacket(IP, ICMPDestinationUnreachable)
        assert i["icmpDestinationUnreachable"]
        i.initialise()
        assert i["icmpDestinationUnreachable"]

    def test_payload(self):
        i = createPacket(IP, ICMPDestinationUnreachable)
        assert repr(i["icmp"].iphdr)


class uICMPEchoRequest(libpry.AutoTree):
    def test_create(self):
        i = createPacket(IP, ICMPEchoRequest)
        assert i["icmpEchoRequest"]
        i.initialise()
        assert i["icmpEchoRequest"]
    
    def test_payload(self):
        i = createPacket(IP, ICMPEchoRequest)
        expected = "Count FruFru"
        i["icmp"].payload = expected
        i.finalise()
        assert i["icmp"].payload ==  expected


class uICMPTimestampRequest(libpry.AutoTree):
    def test_create(self):
        i = createPacket(IP, ICMPTimestampRequest)
        assert i["icmpTimestampRequest"]
        i.initialise()
        assert i["icmpTimestampRequest"]


tests = [
    uLoopback(),
    uEthernet(),
    uARP(),
    uIP(),
    uIPv6(),
    uTCP(),
    uUDP(),
    uICMPDestinationUnreachable(),
    uICMPEchoRequest(),
    uICMPTimestampRequest(),
]
