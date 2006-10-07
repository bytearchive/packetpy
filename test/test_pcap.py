import unittest, os, sys
import packet.pcap

class TestError(Exception): pass

def dumper(*args):
    print args

def nullFunc(*args):
    pass

def errFunc(*args):
    raise packet.pcap.PcapError(1)


class uBPFProgram(unittest.TestCase):
    def setUp(self):
        self.l = packet.pcap.Offline("pcap_data/tdump")

    def test_no_feed_connected(self):
        self.l.close()
        self.failUnlessRaises(packet.pcap.PcapError, packet.pcap.BPFProgram, self.l, "")

    def test_bad_init(self):
        self.failUnlessRaises(packet.pcap.PcapError, packet.pcap.BPFProgram, self.l, "intentionally erroneous")

    def test_compile(self):
        packet.pcap.BPFProgram(self.l, "icmp")
        self.failUnlessRaises(packet.pcap.PcapError, packet.pcap.BPFProgram, self.l, "asdf")


class uPcapOffline(unittest.TestCase):
    def setUp(self):
        self.l = packet.pcap.Offline("pcap_data/tdump")

    def test_next(self):
        self.failUnless(self.l.next(1))

    def test_loop(self):
        self.l.loop(5, nullFunc)

    def test_loopError(self):
        self.failUnlessRaises(packet.pcap.PcapError, self.l.loop, -1, errFunc)

    def test_dispatch(self):
        self.l.dispatch(5, nullFunc)

    def test_dispatchError(self):
        self.failUnlessRaises(packet.pcap.PcapError, self.l.dispatch, -1, errFunc)

    def test___int__(self):
        self.failUnless(int(self.l)==self.l.fileno())

    #def test__setfilter(self):
        ## The _pcap library causes a segment fault when this test is run
        #self.bpf = packet.pcap.BPFProgram(self.l, "")
        #self.l.close()
        #self.failUnlessRaises(packet.pcap.PcapError, self.l._setfilter, self.bpf)

    def test_datalink(self):
        self.failUnlessEqual(self.l.datalink(), 1)

    def test_close(self):
        self.l.close()

    def test_alreadyClosedError(self):
        self.l.close()
        self.failUnlessRaises(packet.pcap.PcapError, self.l.datalink)
        self.failUnlessRaises(packet.pcap.PcapError, self.l.close)
        self.failUnlessRaises(packet.pcap.PcapError, self.l.dispatch, 2, nullFunc)
        self.failUnlessRaises(packet.pcap.PcapError, self.l.loop, 2, nullFunc)
        del self.l

    def test_handlerError(self):
        """
            Test handler raising an error.
        """
        def errHandler(*args):
            raise TestError
        self.failUnlessRaises(TestError, self.l.loop, 5, errHandler)

    def test_lookupnet(self):
        self.failUnless(self.l.lookupnet() == (0, 0))

    def test_filter(self):
        self.l.filter("icmp")

    def test_is_swapped(self):
        if sys.byteorder == "little":
            self.failIf(self.l.is_swapped())
        else:
            self.failUnless(self.l.is_swapped())

    def test_version(self):
        self.failUnlessEqual(self.l.version(), (2, 4))

    def test_fileno(self):
        self.failUnless(self.l.fileno() > 0)

    def test_bad_dump(self):
        self.failUnlessRaises(packet.pcap.PcapError, packet.pcap.Offline, "pcap_data/bad_dump")

    #def test_bad_dlt(self):
        ## This will require a packet with a deliberately crafted invalid DLT identifier
        #self.l = packet.pcap.Offline("pcap_data/ff_dump")
        #self.failUnlessRaises(packet.pcap.PcapError, self.l.loop, 1, nullFunc, 1)


if os.geteuid() == 0:
    class uPcapLive(unittest.TestCase):
        """
            These tests have to be run with superuser privs...
        """
        def setUp(self):
            self.l = packet.pcap.Live()

        def tearDown(self):
            self.l.close()

        def test_inject(self):
            def injector(packet, *args):
                self.l.inject(packet)
            # We re-inject packets from our dump:
            d = packet.pcap.Offline("pcap_data/tdump")
            d.loop(5, injector)

        def test_lookupnet(self):
            self.failUnless(self.l.lookupnet())

        def test_snapshot(self):
            self.failUnlessEqual(self.l.snapshot(), self.l.snaplen)

        def test_stats(self):
            self.failUnless(self.l.stats())
    

class uPcapDump(unittest.TestCase):
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

    def test_dump(self):
        self.l.loop(5, self.d)
        self.d.close()

        # Now we read our output back:
        reader = packet.pcap.Offline("pcap_data/output")
        self.failUnlessEqual(reader.datalink(), 1)
        reader.loop(5, nullFunc)

    def test_doublecloseError(self):
        self.d.close()
        self.failUnlessRaises(packet.pcap.PcapError, self.d.close)
        del self.d


class PacketCap:
    def __init__(self):
        self.packets = []

    def __call__(self, packet, tstamp, length):
        self.packets.append(packet)

class uPacketFactory(unittest.TestCase):
    def test_ethernet(self):
        feed = packet.pcap.Offline("pcap_data/ethernet")
        tf = PacketCap()
        feed.loop(10, tf, 1)
        for i in tf.packets:
            self.failUnlessEqual(i.protostack._TYPE, "Ethernet")

    def test_pf(self):
        feed = packet.pcap.Offline("pcap_data/pf")
        tf = PacketCap()
        feed.loop(10, tf, 1)
        for i in tf.packets:
            self.failUnlessEqual(i.protostack._TYPE, "PF")

    def test_loop(self):
        feed = packet.pcap.Offline("pcap_data/loop")
        tf = PacketCap()
        feed.loop(10, tf, 1)
        for i in tf.packets:
            self.failUnlessEqual(i.protostack._TYPE, "Loopback")

    def test_pfold(self):
        feed = packet.pcap.Offline("pcap_data/pf.old")
        tf = PacketCap()
        feed.loop(10, tf, 1)
        for i in tf.packets:
            self.failUnlessEqual(i.protostack._TYPE, "PFOld")


class uMisc(unittest.TestCase):
    def test_isPCapFile(self):
        self.failIf(packet.pcap.isPCapFile("test_pcap.py"))
        self.failUnless(packet.pcap.isPCapFile("pcap_data/pf"))

