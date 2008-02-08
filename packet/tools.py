import sys, os
import pcap

class Splitter:
    """
        Splitter splits a set of log files into n approximately equal chunks.
        Files are written to a specified destination path, with a numeric
        extension appended.
    """
    def callback(self, pack, ts, length):
        if not self.dumper or self.dumper.ftell() > self.partsize:
            if self.dumper:
                self.dumper.close()
                self.nfile += 1
            self.packetcounter = 0
            fname = self.dst + ".%0.3i"%self.nfile
            self.outfiles.append(fname)
            self.dumper = packet.pcap.Dumper(
                packet.pcap.Dead(self.datalink),
                fname
            )
            self.newfile(fname)
        self.packetcounter += 1
        self.dumper(pack, ts, length)
        self.tick(packetcounter, self.dumper.ftell())

    def __call__(self, files, n, dst):
        self.dst = dst
        self.totalsize = 0
        for i in files:
            self.totalsize += os.stat(i).st_size
        self.partsize = self.totalsize/float(n)
        self.dumper = None
        self.nfile = 0
        self.datalink = None
        self.outfiles = []

        for i in self.files:
            f = packet.pcap.Offline(i)
            self.datalink = f.datalink()
            f.loop(-1, self.callback)
        self.dumper.close()
        self.done()
        return self.outfiles

    def newfile(self, fname):
        """
            Hook method that gets called every time a new destination file is
            opened for writing.
        """
        pass

    def tick(self, packets, bytes):
        """
            Hook method that gets called every time a packet is written to a
            destination file.

            packets: The number of packets in the current destination file.
            bytes:   The number of bytes in the current destination file.
        """
        pass

    def done(self):
        """
            Hook method that gets called after the last destination file is
            closed. 
        """
        pass
