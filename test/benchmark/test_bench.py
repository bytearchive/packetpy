import os.path
import libpry
import packet.pcap

class uBench(libpry.AutoTree):
    def test_packet_construction(self):
        if not os.path.isfile("target"):
            s = "Please place a file named 'target' in the benchmark directory."
            raise ValueError(s)
        def callback(*args):
            pass
        d = packet.pcap.Offline("target")
        d.loop(-1, callback, interpret=True)
        d.close()


tests = [
    uBench()
]
