import libpry
import array
import packet.packet
import pcaptester

class PseudoPacket:
    def __init__(self, data):
        self._data = data

    def __len__(self):
        return len(self._data)


class uProtocolSplicing(pcaptester.pcapTester):
    dump = "icmp_echo_reply"
    def test_splice(self):
        self.data["ip"]._splice(12, 16, "\0\0\0\0")
        assert self.data["ip"].src == "0.0.0.0"


class uProtocol(libpry.AutoTree):
    def setUp(self):
        self.tstr = array.array("c", "".join([chr(i) for i in range(255)]))
        pkt = PseudoPacket(self.tstr)
        self.p = packet.packet.Protocol(pkt)
        
    def test_getByteField(self):
        x = self.p._getByteField(0, 10)
        assert [ord(i) for i in x] == range(10)

    def test_getByteFieldOff(self):
        pkt = PseudoPacket(self.tstr)
        p = packet.packet.Protocol(pkt, 10)
        x = p._getByteField(0, 10)
        assert [ord(i) for i in x] == range(10, 20)

    def test_setByteField(self):
        v = chr(10)*10
        self.p._setByteField(0, 10, v)
        x = self.p._getByteField(0, 10)
        assert [ord(i) for i in x] == [10]*10
        
    def test_getIntField(self):
        x = self.p._getIntField(0, 4)
        # This should be 0x00010203
        assert x == 66051

    def test_setIntField(self):
        self.p._setIntField(1, 4, 5555)
        x = self.p._getIntField(1, 4)
        assert x == 5555

    def test_getBitField(self):
        pkt = PseudoPacket(self.tstr)
        p = packet.packet.Protocol(pkt)
        assert p._getBitField(0, 3, 5) == 0
        assert p._getBitField(0, 15, 1) == 1
        assert p._getBitField(0, 15, 2) == 2
        assert p._getBitField(0, 15, 3) == 4
        assert p._getBitField(0, 15, 4) == 8
        assert p._getBitField(1, 0, 8) == 1
        assert p._getBitField(2, 0, 8) == 2
        assert p._getBitField(2, 6, 2) == 2
        assert p._getBitField(2, 7, 1) == 0

    def test_setBitField(self):
        self.p._setBitField(0, 3, 5, 5)
        assert self.p._getBitField(0, 3, 5) == 5

        self.p._setBitField(0, 3, 8, 5)
        assert self.p._getBitField(0, 3, 8) == 5

        self.p._setBitField(5, 3, 8, 5)
        assert self.p._getBitField(5, 3, 8) == 5

        # Now test that adjacent bits remain intact
        self.p._setBitField(1, 0, 7, 0)
        assert self.p._getBitField(1, 7, 1) == 1

    def test_setBitFieldErr(self):
        libpry.raises(ValueError,  self.p._setBitField, 0, 0, 1, 3)
        libpry.raises(ValueError,  self.p._setBitField, 0, 0, 8, 256)

    def test_repr(self):
        repr(self.p)


class uProtocolGetitem(pcaptester.pcapTester):
    dump = "icmp_echo_reply"
    def test_getitem(self):
        assert self.data["ip"]["icmp"].TYPE == "ICMPEchoReply"
        assert self.data["icmp"].TYPE == "ICMPEchoReply"

    def test_has_key(self):
        assert self.data.has_key("icmpechoreply")
        assert not self.data.has_key("flibble")


class uProtocolShortenedHeaders(pcaptester.pcapTester):
    dump = "icmp_time_exceeded"
    def test_getitem(self):
        libpry.raises(
            packet.packet.DataBoundsError,
            getattr,
            self.data["icmp"].iphdr, "payload"
        )


class uPacket(pcaptester.pcapTester):
    dump = "icmp_echo_reply"
    def test_getitem(self):
        assert self.data["ip"].TYPE == "IP"
        assert self.data["icmp"].TYPE
        assert self.data["icmpecho"].TYPE
        libpry.raises(KeyError, self.data.__getitem__, "moomoo")

    def test_finalise(self):
        self.data.finalise()

    def test_getRaw(self):
        assert self.data.getRaw()


tests = [
    uPacket(),
    uProtocolSplicing(),
    uProtocol(),
    uProtocolGetitem(),
    uProtocolShortenedHeaders(),
]
