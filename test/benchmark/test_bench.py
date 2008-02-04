import libpry
import packet.pcap


class uBench(libpry.AutoTree):
    def test_packet_construction(self):
        def callback(*args):
            pass
        d = packet.pcap.Offline("target")
        d.loop(-1, callback, 1)
        d.close()


tests = [
    uBench()
]
