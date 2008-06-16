import libpry
import os, sys
import packet.pcap
import packet.packet

class TestError(Exception): pass

def dumper(*args):
    print args

def nullFunc(*args):
    pass

def errFunc(*args):
    raise packet.pcap.PcapError(1)


class uInterpreter(libpry.AutoTree):
    def test_init(self):
        libpry.raises(
            "unknown link layer type",
            packet.pcap.Interpreter, "nonexistent", None, None
        )

        p = packet.pcap.Interpreter(
            1,
            None,
            packet.packet.Ethernet
        )
        assert p.pclass == packet.packet.Ethernet


class uBPFProgram(libpry.AutoTree):
    def setUp(self):
        self.l = packet.pcap.Offline("pcap_data/tdump")

    def test_no_feed_connected(self):
        self.l.close()
        libpry.raises(packet.pcap.PcapError, packet.pcap.BPFProgram, self.l, "")

    def test_bad_init(self):
        libpry.raises(
            packet.pcap.PcapError,
            packet.pcap.BPFProgram,
            self.l,
            "intentionally erroneous"
        )

    def test_compile(self):
        packet.pcap.BPFProgram(self.l, "icmp")
        libpry.raises(
            packet.pcap.PcapError,
            packet.pcap.BPFProgram,
            self.l,
            "asdf"
        )

    def test_fseek(self):
        l = packet.pcap.Offline("pcap_data/tdump")
        pos = l.ftell()
        p = l.next()
        l.fseek(pos)
        p2 = l.next()
        assert p == p2


class uPcapOffline(libpry.AutoTree):
    def setUp(self):
        self.l = packet.pcap.Offline("pcap_data/tdump")

    def test_next(self):
        assert self.l.next(1)

    def test_loop(self):
        self.l.loop(5, nullFunc)

    def test_loopError(self):
        libpry.raises(packet.pcap.PcapError, self.l.loop, -1, errFunc)

    def test_dispatch(self):
        self.l.dispatch(5, nullFunc)

    def test_dispatchError(self):
        libpry.raises(packet.pcap.PcapError, self.l.dispatch, -1, errFunc)

    def test___int__(self):
        assert int(self.l)==self.l.fileno()

    def test__setfilter(self):
        bpf = packet.pcap.BPFProgram(self.l, "icmp")
        self.l.close()
        libpry.raises("not connected", self.l._setfilter, bpf)

    def test_datalink(self):
        assert self.l.datalink() ==  1

    def test_close(self):
        self.l.close()

    def test_alreadyClosedError(self):
        self.l.close()
        libpry.raises(packet.pcap.PcapError, self.l.datalink)
        libpry.raises(packet.pcap.PcapError, self.l.close)
        libpry.raises(packet.pcap.PcapError, self.l.dispatch, 2, nullFunc)
        libpry.raises(packet.pcap.PcapError, self.l.loop, 2, nullFunc)
        del self.l

    def test_handlerError(self):
        """
            Test handler raising an error.
        """
        def errHandler(*args):
            raise TestError
        libpry.raises(TestError, self.l.loop, 5, errHandler)

    def test_lookupnet(self):
        # NOTE: This test may fail validly if we have no IP addresses assigned
        assert self.l.lookupnet() == (0, 0)

    def test_filter(self):
        self.l.filter("icmp")

    def test_is_swapped(self):
        if sys.byteorder == "little":
            assert not self.l.is_swapped()
        else:
            assert self.l.is_swapped()

    def test_version(self):
        assert self.l.version(), (2 ==  4)

    def test_fileno(self):
        assert self.l.fileno() > 0

    def test_fileno(self):
        assert self.l.ftell()
        self.l.close()

    def test_bad_dump(self):
        libpry.raises(
            packet.pcap.PcapError,
            packet.pcap.Offline,
            "pcap_data/bad_dump"
        )


class uDead(libpry.AutoTree):
    """
        These tests have to be run with superuser privs...
    """
    def setUp(self):
        self.l = packet.pcap.Dead(packet.packet.Ethernet)

    def test_foo(self):
        assert self.l.datalink() == packet.pcap.DLTLookup[packet.packet.Ethernet]


class uLive(libpry.AutoTree):
    """
        These tests have to be run with superuser privs...
    """
    def setUp(self):
        self.l = packet.pcap.Live()

    def tearDown(self):
        try:
            self.l.close()
        except packet.pcap.PcapError:
            pass

    def test_inject(self):
        def injector(packet, *args):
            self.l.inject(packet)
        # We re-inject packets from our dump:
        d = packet.pcap.Offline("pcap_data/tdump")
        d.loop(5, injector)

    def test_lookupnet(self):
        assert self.l.lookupnet()

    def test_snapshot(self):
        assert self.l.snapshot() ==  self.l.snaplen

    def test_stats(self):
        assert self.l.stats()
        self.l.close()
        libpry.raises("not connected", self.l.stats)
    
    def test_err(self):
        libpry.raises("no such device", packet.pcap.Live, interface="nonexistent")


class uDumper(libpry.AutoTree):
    def setUp(self):
        self.l = packet.pcap.Offline("pcap_data/tdump")
        self.d = packet.pcap.Dumper(self.l, "pcap_data/output")

    def tearDown(self):
        try:
            os.remove("pcap_data/output")
        except OSError:
            pass

    def test_close(self):
        self.d.close()

    def test_del(self):
        del self.d

    def test_err(self):
        libpry.raises(
            "is a directory",
            packet.pcap.Dumper, self.l, "pcap_data"
        )

    def test_dump(self):
        self.l.loop(5, self.d)
        assert self.d.ftell()
        self.d.close()

        # Now we read our output back:
        reader = packet.pcap.Offline("pcap_data/output")
        assert reader.datalink() ==  1
        reader.loop(5, nullFunc)

    def test_doublecloseError(self):
        self.d.close()
        libpry.raises(packet.pcap.PcapError, self.d.close)
        del self.d


class PacketCap:
    def __init__(self):
        self.packets = []

    def __call__(self, packet, tstamp, length):
        self.packets.append(packet)

class uPacketFactory(libpry.AutoTree):
    def test_ethernet(self):
        feed = packet.pcap.Offline("pcap_data/ethernet")
        tf = PacketCap()
        feed.loop(10, tf, 1)
        for i in tf.packets:
            assert i.protostack.TYPE ==  "Ethernet"

    def test_pf(self):
        feed = packet.pcap.Offline("pcap_data/pf")
        tf = PacketCap()
        feed.loop(10, tf, 1)
        for i in tf.packets:
            assert i.protostack.TYPE ==  "PF"

    def test_loop(self):
        feed = packet.pcap.Offline("pcap_data/loop")
        tf = PacketCap()
        feed.loop(10, tf, 1)
        for i in tf.packets:
            assert i.protostack.TYPE ==  "Loopback"

    def test_pfold(self):
        feed = packet.pcap.Offline("pcap_data/pf.old")
        tf = PacketCap()
        feed.loop(10, tf, 1)
        for i in tf.packets:
            assert i.protostack.TYPE ==  "PFOld"


class uMisc(libpry.AutoTree):
    def test_isPCapFile(self):
        assert not packet.pcap.isPCapFile("test_pcap.py")
        assert packet.pcap.isPCapFile("pcap_data/pf")


tests = [
    uInterpreter(),
    uBPFProgram(),
    uPcapOffline(),
    uDumper(),
    uDead(),
    uPacketFactory(),
    uMisc(),
]
if os.geteuid() == 0:
    tests.append(uLive())
