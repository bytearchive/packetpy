import libpry
import os.path
from packet import pcap

class pcapTester(libpry.AutoTree):
    DATADIR = "packetdata"
    def __init__(self, dump=None, pclass=None):
        libpry.AutoTree.__init__(self)
        if dump:
            self.dump = dump
        self.pclass = pclass

    def setUp(self):
        dlist = []
        def slurp(data, *args):
            dlist.append(data)
            return dlist
        d = pcap.Offline(os.path.join(self.DATADIR, self.dump))
        # One packet interpreted unless pclass is None
        d.loop(1, slurp, 1, pclass=self.pclass)
        d.close()
        self.data = dlist[0]
