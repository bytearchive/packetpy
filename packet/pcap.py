#    Copyright (c) 2003, Nullcube Pty Ltd
#    All rights reserved.
#
#    Redistribution and use in source and binary forms, with or without
#    modification, are permitted provided that the following conditions are met:
#
#    *   Redistributions of source code must retain the above copyright notice, this
#        list of conditions and the following disclaimer.
#    *   Redistributions in binary form must reproduce the above copyright notice,
#        this list of conditions and the following disclaimer in the documentation
#        and/or other materials provided with the distribution.
#    *   Neither the name of Nullcube nor the names of its contributors may be used to
#        endorse or promote products derived from this software without specific
#        prior written permission.
#
#    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
#    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
#    ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
import sys, datetime
from _global import *
import _pcap
import packet

DLTLookup = {
    #0:          Null,
    1:          packet.Ethernet,
    # OpenBSD Specific
    117:        packet.PF,
    17:         packet.PFOld,
    13:         packet.Enc,
    12:         packet.Loopback
    #DLT_IEEE802     6
    #DLT_RAW         12
}


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
            return _pcap.compile(feed._phandle, filterstr, optimise, feed.lookupnet()[1])
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
        dtime = datetime.datetime.fromtimestamp(tstamp[0] + (float(tstamp[1])/1000000))
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

    def inject(self, packet):
        try:
            _pcap.inject(self._phandle, packet)
        except PcapError, val:
            raise PcapError(val)

    def datalink(self):
        """
            Returns the link layer type. 
        """
        if not self._phandle:
            raise PcapError("Not connected.")
        return _pcap.datalink(self._phandle)

    def _setfilter(self, bpfprog):
        try:
            _pcap.setfilter(self._phandle, bpfprog._bpf)
        except PcapError, val:
            raise PcapError(val)

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


class Live(_PcapFeed):
    """
        Monitor a live interface.
    """
    def __init__(self, interface=None, snaplen=96, promisc=1, timeout=1000):
        """
            If no interface is specified, a suitable interface is automatically chosen.
        """
        _PcapFeed.__init__(self)
        if interface is None:
            try:
                interface = _pcap.lookupdev()
            except PcapError, val:
                raise PcapError(val)
        self.interface, self.snaplen, self.promisc, self.timeout = interface, snaplen, promisc, timeout
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
        except PcapError, val:
            raise PcapError(val)

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

    def __del__(self):
        if self._dhandle:
            self.close()

    def __call__(self, packet, ttuple, length):
        """
            This method has an interface that corresponds to that of the
            callback function for loop and dispatch.
        """
        _pcap.dump(self._dhandle, packet, ttuple, length)
