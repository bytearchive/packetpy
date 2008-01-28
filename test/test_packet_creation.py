import unittest
from packet.packet import *

class uLoopback(unittest.TestCase):
    def test_create(self):
        p = createPacket(Loopback)
        self.failUnlessEqual(len(p.protostack), 1)
        self.failUnlessEqual(p.protostack.TYPE, "Loopback")

    def test_create_nested(self):
        p = createPacket(Loopback, IP)
        self.failUnlessEqual(len(p.protostack), 2)
        self.failUnless(p["ip"])

    def test_payloads(self):
        p = createPacket(Loopback)
        expected = "supercalifragilisticexpialidocious"
        p.payload = expected
        self.failUnlessEqual(p.payload, expected)

    def test_reinitialise(self):
        p = createPacket(Loopback, IP)
        p.initialise()
        self.failUnless(p["ip"])


class uEthernet(unittest.TestCase):
    def test_create(self):
        e = createPacket(Ethernet)
        self.failUnless(e["ethernet"])
        e.initialise()
        self.failUnless(e["ethernet"])

    def test_create_nested(self):
        e = createPacket(Ethernet, IP)
        self.failUnless(e["ip"])
        e.initialise()
        self.failUnless(e["ip"])

    def test_payload(self):
        e = createPacket(Ethernet)
        expected = "foofoo"
        e.payload = expected
        e.initialise()
        self.failUnlessEqual(e.payload, expected)


class uARP(unittest.TestCase):
    def test_create(self):
        a = createPacket(Ethernet, ARP)
        self.failUnless(a["arp"])
        a.initialise()
        self.failUnless(a["arp"])


class uIP(unittest.TestCase):
    def test_create(self):
        a = createPacket(Ethernet, IP)
        self.failUnless(a["ip"])
        a.initialise()
        self.failUnless(a["ip"])

    def test_defaults(self):
        a = createPacket(Ethernet, IP)
        self.failUnlessEqual(a["ip"].version, 4)
        self.failUnless(a["ip"].ttl)

    def test_create_nested(self):
        a = createPacket(Ethernet, IP, TCP)
        self.failUnless(a["tcp"])
        a.initialise()
        self.failUnless(a["tcp"])

    def test_payload(self):
        a = createPacket(Ethernet, IP)
        expected = "Count Frufru"
        a.payload = expected
        a.initialise()
        self.failUnlessEqual(a.payload, expected)


class uIPv6(unittest.TestCase):
    def test_create(self):
        a = createPacket(Ethernet, IPv6)
        self.failUnless(a["ipv6"])
        a.initialise()
        self.failUnless(a["ipv6"])

    def test_defaults(self):
        a = createPacket(Ethernet, IPv6)
        self.failUnlessEqual(a["ipv6"].version, 6)
        self.failUnlessEqual(a["ipv6"].hoplimit, 255)
        self.failUnlessEqual(a["ipv6"].diffservices, 0)

    def test_create_nested(self):
        a = createPacket(Ethernet, IPv6, TCP)
        self.failUnless(a["ipv6"])
        a.initialise()
        self.failUnless(a["tcp"])


class uTCP(unittest.TestCase):
    def test_create(self):
        a = createPacket(Ethernet, IP, TCP)
        self.failUnless(a["ip"])
        a.initialise()
        self.failUnless(a["ip"])


class uUDP(unittest.TestCase):
    def test_create(self):
        a = createPacket(Ethernet, IP, UDP)
        self.failUnless(a["udp"])
        a.initialise()
        self.failUnless(a["udp"])


#
# We only test one of each "flavour" of ICMP packet.
#
class uICMPDestinationUnreachable(unittest.TestCase):
    def test_create(self):
        i = createPacket(IP, ICMPDestinationUnreachable)
        self.failUnless(i["icmpDestinationUnreachable"])
        i.initialise()
        self.failUnless(i["icmpDestinationUnreachable"])

    def test_payload(self):
        i = createPacket(IP, ICMPDestinationUnreachable)
        self.failUnless(repr(i["icmp"].iphdr))


class uICMPEchoRequest(unittest.TestCase):
    def test_create(self):
        i = createPacket(IP, ICMPEchoRequest)
        self.failUnless(i["icmpEchoRequest"])
        i.initialise()
        self.failUnless(i["icmpEchoRequest"])
    
    def test_payload(self):
        i = createPacket(IP, ICMPEchoRequest)
        expected = "Count FruFru"
        i["icmp"].payload = expected
        i.finalise()
        self.failUnlessEqual(i["icmp"].payload, expected)


class uICMPTimestampRequest(unittest.TestCase):
    def test_create(self):
        i = createPacket(IP, ICMPTimestampRequest)
        self.failUnless(i["icmpTimestampRequest"])
        i.initialise()
        self.failUnless(i["icmpTimestampRequest"])
