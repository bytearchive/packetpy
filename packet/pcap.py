# Copyright (c) 2003-2008, Nullcube Pty Ltd
# All rights reserved.
# 
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys, datetime
from _global import *
import _pcap, packet, _utils

DLTLookup = _utils.DoubleAssociation({
    #0:          Null,
    1:          packet.Ethernet,
    # OpenBSD Specific
    117:        packet.PF,
    17:         packet.PFOld,
    13:         packet.Enc,
    12:         packet.Loopback
    #DLT_IEEE802     6
    #DLT_RAW         12
})

def isPCapFile(fname):
    try:
        Offline(fname)
    except PcapError:
        return 0
    return 1


class BPFProgram:
    """
        A class encapsulating a compiled BPF program.
    """
    def __init__(self, feed, filterstr, optimise=1):
        self.feed, self.filterstr, self.optimise = feed, filterstr, optimise
        try:
            self._bpf = self._compile(feed, filterstr, optimise)
        except PcapError, val:
            raise PcapError(val)

    def _compile(self, feed, filterstr, optimise):
        """
            Compiles a BPF filter, and returns a handle to the compiled struct.

            This method will usually not be used externally - you probably want
            the filter method on the Live and Offline classes instead.
        """
        if not feed._phandle:
            raise PcapError("Feed not connected.")
        try:
            return _pcap.compile(
                        feed._phandle,
                        filterstr,
                        optimise,
                        feed.lookupnet()[1]
                    )
        except PcapError, val:
            raise PcapError(val)


class Interpreter:
    def __init__(self, dlt, callback, pclass=None):
        if not pclass:
            try:
                self.pclass = DLTLookup[dlt]
            except KeyError:
                raise PcapError, "Unknown link layer type: %s"%dlt
        else:
            self.pclass = pclass
        self.callback = callback

    def __call__(self, pkt, tstamp, length):
        p = packet.Packet(self.pclass, pkt)
        dtime = datetime.datetime.fromtimestamp(
                    tstamp[0] + (float(tstamp[1])/1000000)
                )
        self.callback(p, dtime, length)
        

class _PcapFeed:
    """
        Parent class of all pcap feeds (i.e. dump files for reading, and live
        interfaces).
    """
    _nextVal = None
    def __init__(self):
        self._phandle = None

    def loop(self, cnt, callback, interpret=0, pclass=None):
        """
            The callback function has the following format:
                callback(packet, timestamp, length)

            Where length is the total length of the packet, and len(packet) is
            the actual amount of data captured.

            If the interpret parameter is true, the packet argument to the
            callback function will be a PacketPy packet object, and the
            timestamp will be a standard Python datetime object. Otherwise, the
            packet is binary data, and the timestamp is a tuple of the form
            (sec, usec).
        """
        if not self._phandle:
            raise PcapError("Not connected.")
        if interpret:
            callback = Interpreter(self.datalink(), callback, pclass)
        try:
            _pcap.loop(self._phandle, cnt, callback)
        except PcapError, val:
            raise PcapError(val)

    def dispatch(self, cnt, callback, interpret=0, pclass=None):
        """
            The callback function has the following format:
                callback(packet, timestamp, length)

            Where length is the total length of the packet, and len(packet) is
            the actual amount of data captured.

            If the interpret parameter is true, the packet argument to the
            callback function will be a PacketPy packet object, and the
            timestamp will be a standard Python datetime object. Otherwise, the
            packet is binary data, and the timestamp is a tuple of the form
            (sec, usec).
        """
        if not self._phandle:
            raise PcapError("Not connected.")
        if interpret:
            callback = Interpreter(self.datalink(), callback, pclass)
        try:
            _pcap.dispatch(self._phandle, cnt, callback)
        except PcapError, val:
            raise PcapError(val)

    def next(self, interpret=0):
        def myget(*args):
            self._nextVal = args
        self.dispatch(1, myget, interpret)
        # Don't keep a reference the user doesn't expect...
        x = self._nextVal
        self._nextVal = None 
        return x

    #begin nocover
    def inject(self, packet):
        try:
            _pcap.inject(self._phandle, packet)
        except PcapError, val:
            raise PcapError(val)
    #end nocover

    def datalink(self):
        """
            Returns the link layer type. 
        """
        if not self._phandle:
            raise PcapError("Not connected.")
        return _pcap.datalink(self._phandle)

    def _setfilter(self, bpfprog):
        if not self._phandle:
            raise PcapError("Not connected.")
        try:
            _pcap.setfilter(self._phandle, bpfprog._bpf)
        #begin nocover
        except PcapError, val:
            raise PcapError(val)
        #end nocover

    def filter(self, filterstr):
        bpf = BPFProgram(self, filterstr)
        self._setfilter(bpf)

    def close(self):
        if not self._phandle:
            raise PcapError("Not connected.")
        _pcap.close(self._phandle)
        self._phandle = None

    def __del__(self):
        if self._phandle:
            self.close()


class Dead(_PcapFeed):
    """
        A dummy interface.
    """
    def __init__(self, linktype, snaplen=1500):
        if not isinstance(linktype, int):
            linktype = DLTLookup[linktype]
        self._phandle = _pcap.open_dead(linktype, snaplen)


class Live(_PcapFeed):
    """
        Monitor a live interface.
    """
    def __init__(self, interface=None, snaplen=96, promisc=1, timeout=1000):
        """
            If no interface is specified, a suitable interface is automatically
            chosen.
        """
        _PcapFeed.__init__(self)
        if interface is None:
            try:
                interface = _pcap.lookupdev()
            #begin nocover
            except PcapError, val:
                raise PcapError(val)
            #end nocover
        self.interface, self.snaplen = interface, snaplen
        self.promisc, self.timeout =  promisc, timeout
        try:
            self._phandle = _pcap.open_live(interface, snaplen, promisc, timeout)
        except PcapError, val:
            raise PcapError(val)

    def lookupnet(self):
        """
            Returns a (net, mask) tuple.
        """
        try:
            return _pcap.lookupnet(self.interface)
        #begin nocover
        except PcapError, val:
            raise PcapError(val)
        #end nocover

    def snapshot(self):
        """
            Returns the snapshot length specified when Live was instantiated.
            This method is redundant, since the snapshot length can also be
            obtained by simply checking self.snaplen.
        """
        return _pcap.snapshot(self._phandle)

    def stats(self):
        if not self._phandle:
            raise PcapError("Not connected.")
        return _pcap.stats(self._phandle)


class Offline(_PcapFeed):
    def __init__(self, filename):
        _PcapFeed.__init__(self)
        self.filename = filename
        try:
            self._phandle = _pcap.open_offline(filename)
        except PcapError, val:
            raise PcapError(val)

    def __int__(self):
        return self.fileno()

    def lookupnet(self):
        """
            Returns a (net, mask) tuple. For offline feeds this is always 
            (0, 0).
        """
        return 0, 0

    def is_swapped(self):
        """
            Is the byte order of the save file different from that of
            the current system?
        """
        return _pcap.is_swapped(self._phandle)

    def version(self):
        """
            Return the major and minor versions of the pcap used to write the
            save file.
        """
        return _pcap.version(self._phandle)

    def fileno(self):
        return _pcap.fileno(self._phandle)

    def ftell(self):
        return _pcap.ftell(self._phandle)


class Dumper:
    def __init__(self, feed, filename):
        self.feed, self.filename = feed, filename
        try:
            self._dhandle = _pcap.dump_open(feed._phandle, filename)
        except PcapError, val:
            raise PcapError(val)

    def close(self):
        if not self._dhandle:
            raise PcapError("Dumper already closed.")
        _pcap.dump_close(self._dhandle)
        self._dhandle = None

    def ftell(self):
        """
            Byte offset of dump file.
        """
        if not self._dhandle:
            raise PcapError("Dumper already closed.")
        return _pcap.dump_ftell(self._dhandle)

    def __del__(self):
        if self._dhandle:
            self.close()

    def __call__(self, packet, ttuple, length):
        """
            This method has an interface that corresponds to that of the
            callback function for loop and dispatch.
        """
        _pcap.dump(self._dhandle, packet, ttuple, length)
