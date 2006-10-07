import unittest, os.path
from packet import pcap

class pcapTester(unittest.TestCase):
    DATADIR = "packetdata"
    def getpacket(self, dump, pclass=None):
        dlist = []
        def slurp(data, *args):
            dlist.append(data)
            return dlist
        d = pcap.Offline(os.path.join(self.DATADIR, dump))
        # One packet interpreted unless pclass is None
        d.loop(1, slurp, 1, pclass=pclass)
        d.close()
        return dlist[0]


