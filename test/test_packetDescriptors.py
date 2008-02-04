import libpry
import array
import packet, packet._packetDescriptors
import pcaptester

class uOptions(libpry.AutoTree):
    def test_getset(self):
        i = packet._packetDescriptors.Options(fOo = 1)
        assert i["foo"] ==  1
        i["foo"] = 2
        assert i["Foo"] ==  2

    def test_haskey(self):
        i = packet._packetDescriptors.Options(fOo = 1)
        assert i.has_key("foo")
        assert i.has_key("Foo")

    def test_keys(self):
        i = packet._packetDescriptors.Options(fOo=1, bAr=2)
        k = i.keys()
        k.sort()
        assert k, ["bAr" ==  "fOo"]

    def test_values(self):
        i = packet._packetDescriptors.Options(fOo=1, bAr=2)
        v = i.values()
        v.sort()
        assert v, [1 ==  2]

    def test_toStr(self):
        i = packet._packetDescriptors.Options(fOo=1, bAr=2)
        assert i.toStr(1) ==  "fOo"
        assert i.toStr(8) ==  "8"
        
    def test_repr(self):
        i = packet._packetDescriptors.Options(fOo=1, bAr=2)
        assert repr(i), "Options(fOo=1 == bAr=2)"

class DummyProtocol(packet.packet.Protocol):
    TYPE = "dummy"
    intfieldOptions = packet._packetDescriptors.Options(
                                                        one     = 1,
                                                        two     = 2,
                                                        three   = 3
                                                )
    intfield = packet._packetDescriptors.IntField(0, 2, doc="test", options=intfieldOptions)
    intfieldNoOpts = packet._packetDescriptors.IntField(2, 4, doc="test")
    flagfieldOptions = packet._packetDescriptors.Options(
                                                        one     = 1,
                                                        two     = 2,
                                                        four    = 4
                                                )
    flagfield = packet._packetDescriptors.FlagsField(4, 0, 8, doc="test", options=flagfieldOptions)
    flagfieldNoOpts = packet._packetDescriptors.FlagsField(5, 0, 8, doc="test")

    # Other protocols here so we can test their docstrings:
    bytefield       = packet._packetDescriptors.ByteField(10, 4, doc="test")
    paddedstring    = packet._packetDescriptors.PaddedString(10, 4, doc="test")
    bitfield        = packet._packetDescriptors.BitField(10, 4, 4, doc="test")
    ethernetaddr    = packet._packetDescriptors.EthernetAddress(10, doc="test")
    ipaddr          = packet._packetDescriptors.IPAddress(10, doc="test")
    ip6addr         = packet._packetDescriptors.IPv6Address(10, doc="test")
    hoint32         = packet._packetDescriptors.HOInt32Field(26, doc="test", options=intfieldOptions)
    hoint32flags    = packet._packetDescriptors.HOInt32FlagsField(26, doc="test", options=flagfieldOptions)
    payload         = packet._packetDescriptors.Payload(doc="test")
    proxy           = packet._packetDescriptors.DescriptorProxy("foo", doc="test")
    ipaddresslist   = packet._packetDescriptors.IPAddressList(0, 4, doc="test")

    def _getPayloadOffsets(self):
        return 30, 4

def makeDummy():
    return packet.packet.Packet(DummyProtocol, "\0"*34)


class _DescTester(libpry.AutoTree):
    def setUp(self):
        self.p = makeDummy()
    

class uIntField(_DescTester):
    def test_normal(self):
        assert self.p["dummy"].intfield ==  0
        self.p["dummy"].intfield = 20
        assert self.p["dummy"].intfield ==  20

    def test_options(self):
        self.p["dummy"].intfield = "one"
        assert self.p["dummy"].intfield ==  1
        self.p["dummy"].intfield = "Two"
        assert self.p["dummy"].intfield ==  2

    def test_doc(self):
        assert DummyProtocol.intfieldNoOpts ==  None
        DummyProtocol.intfield

    def test_getNone(self):
        DummyProtocol.intfield


class uHOInt32Field(_DescTester):
    def test_normal(self):
        assert self.p["dummy"].hoint32 ==  0
        self.p["dummy"].hoint32 = 20
        assert self.p["dummy"].hoint32 ==  20

    def test_options(self):
        self.p["dummy"].hoint32 = "one"
        assert self.p["dummy"].hoint32 ==  1
        self.p["dummy"].hoint32 = "Two"
        assert self.p["dummy"].hoint32 ==  2


class uByteField(_DescTester):
    def test_doc(self):
        assert DummyProtocol.bytefield ==  None

    def test_set(self):
        self.p["dummy"].bytefield = "\0"

    def test_get(self):
        self.p["dummy"].bytefield


class uPaddedString(_DescTester):
    def test_doc(self):
        assert DummyProtocol.paddedstring ==  None

    def test_set(self):
        self.p["dummy"].paddedstring = "foo"

    def test_get(self):
        self.p["dummy"].paddedstring


class uBitField(_DescTester):
    def test_doc(self):
        assert DummyProtocol.bitfield ==  None

    def test_set(self):
        self.p["dummy"].bitfield = 1

    def test_get(self):
        self.p["dummy"].bitfield


class uPayload(_DescTester):
    def test_doc(self):
        assert DummyProtocol.payload ==  None

    def test_get(self):
        self.p["dummy"].payload

    def test_set(self):
        self.p["dummy"].payload = "foo"
        


class uDescriptorProxy(_DescTester):
    def test_doc(self):
        assert DummyProtocol.proxy ==  None


class uFlagsField(_DescTester):
    def test_normal(self):
        assert self.p["dummy"].flagfield ==  0
        self.p["dummy"].flagfield = 20
        assert self.p["dummy"].flagfield ==  20

    def test_options_str(self):
        self.p["dummy"].flagfield = "one"
        assert self.p["dummy"].flagfield ==  1
        self.p["dummy"].flagfield = "Two"
        assert self.p["dummy"].flagfield ==  2

    def test_options_list(self):
        self.p["dummy"].flagfield = ["one", "two"]
        assert self.p["dummy"].flagfield ==  3
        self.p["dummy"].flagfield = ["Two"]
        assert self.p["dummy"].flagfield ==  2

    def test_getNone(self):
        DummyProtocol.flagfield


class uHOInt32FlagsField(_DescTester):
    def test_normal(self):
        assert self.p["dummy"].hoint32flags ==  0
        self.p["dummy"].hoint32flags = 20
        assert self.p["dummy"].hoint32flags ==  20

    def test_options_str(self):
        self.p["dummy"].hoint32flags = "one"
        assert self.p["dummy"].hoint32flags ==  1
        self.p["dummy"].hoint32flags = "Two"
        assert self.p["dummy"].hoint32flags ==  2

    def test_options_list(self):
        self.p["dummy"].hoint32flags = ["one", "two"]
        assert self.p["dummy"].hoint32flags ==  3
        self.p["dummy"].hoint32flags = ["Two"]
        assert self.p["dummy"].hoint32flags ==  2


class uEthernetAddress(pcaptester.pcapTester):
    dump = "tcp"
    def test_set(self):
        libpry.raises(
            ValueError,
            setattr,
            self.data["ethernet"],
            "src",
            "aaa:a:a:a:a:a"
        )
        libpry.raises(
            ValueError,
            setattr,
            self.data["ethernet"],
            "src",
            "a:a:a:a:a"
        )

    def test_get(self):
        p = makeDummy()
        p["dummy"].ethernetaddr

    def test_doc(self):
        assert repr(DummyProtocol.ethernetaddr)


class uIPAddress(pcaptester.pcapTester):
    dump = "icmp_echo_reply"
    def setUp(self):
        pcaptester.pcapTester.setUp(self)
        self.ip = self.data["ip"]

    def test_set(self):
        libpry.raises(ValueError, setattr, self.ip, "src", "1.1.1")
        libpry.raises(ValueError, setattr, self.ip, "src", "1.1.1.300")
        libpry.raises(ValueError, setattr, self.ip, "src", "1.1.1.a")
        self.ip.src = "1.1.1.1"

    def test_get(self):
        self.ip.src

    def test_doc(self):
        assert DummyProtocol.ipaddr ==  None


class uIPv6Address(pcaptester.pcapTester):
    dump = "icmp6_echorequest"
    def test_set(self):
        libpry.raises(ValueError, setattr, self.data["ipv6"], "src", "::1::1")
        libpry.raises(ValueError, setattr, self.data["ipv6"], "src", "::123422")
        libpry.raises(ValueError, setattr, self.data["ipv6"], "src", "::123422")
        libpry.raises(ValueError, setattr, self.data["ipv6"], "src", "1:1:1:1:1::1:1:1:1")

    def test_set_noerr(self):
        self.data["ipv6"].src = ("::1")
        assert self.data["ipv6"].src ==  "::1"
        self.data["ipv6"].src = ("1::")
        assert self.data["ipv6"].src ==  "1::"
        self.data["ipv6"].src = ("1:2:3::")
        assert self.data["ipv6"].src ==  "1:2:3::"
        self.data["ipv6"].src = ("1:2:3:4:5:6:7:8")
        assert self.data["ipv6"].src ==  "1:2:3:4:5:6:7:8"

    def test_abbreviation(self):
        self.data["ipv6"].src = ("0:0:0:0:0:0:0:1")
        assert self.data["ipv6"].src ==  "::1"
        self.data["ipv6"].src = ("1:0:0:0:0:0:0:1")
        assert self.data["ipv6"].src ==  "1::1"
        self.data["ipv6"].src = ("fe:80:0:0:0:0:0:1")
        assert self.data["ipv6"].src ==  "fe:80::1"

    def test_doc(self):
        assert DummyProtocol.ip6addr ==  None


class uIPAddressList(pcaptester.pcapTester):
    dump = "ip_recordroute"
    def test_get(self):
        expected = [
                "0.255.255.255",
                "255.168.188.191",
                "207.140.188.191",
                "207.5.75.0",
                "28.1.0.0",
                "0.0.16.0",
                "0.236.188.191",
                "207.47.74.0",
                "28.0.0.0"
        ]
        assert self.data["ip"].options.addrlist ==  expected

    def test_set(self):
        expected = [
            "192.168.0.1",
            "192.168.0.2"
        ]
        self.data["ip"].options.addrlist = expected
        assert self.data["ip"].options.addrlist ==  expected

    def test_initerr(self):
        libpry.raises(ValueError, packet._packetDescriptors.IPAddressList, 1, 5)

    def test_get_none(self):
        DummyProtocol.ipaddresslist


tests = [
    uOptions(),
    uIntField(),
    uHOInt32Field(),
    uByteField(),
    uPaddedString(),
    uBitField(),
    uPayload(),
    uDescriptorProxy(),
    uFlagsField(),
    uHOInt32FlagsField(),
    uEthernetAddress(),
    uIPAddress(),
    uIPv6Address(),
    uIPAddressList(),
]
