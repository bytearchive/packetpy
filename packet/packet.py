#    Copyright (c) 2003, 2004, 2005, 2006 Aldo Cortesi
#    Copyright (c) 2003, David Harrison
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
#    *   Neither the name of Nullcube nor the names of its contributors, nor the
#        name of David Harrison may be used to
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
"""
    PacketPy is a pure-Python module for parsing, modifying and creating
    network packets.
"""
#        TODO:
#            - Documentation
#                - The Packet class should have a fairly complete explanation in
#                  the Countershape docs (has been roughed out now)
#                - Descriptors, classes, RFC references
#                - Expand in-code documentation for use with pydoc. 
#            - 100% unit test coverage.
#            - Better support for IP and TCP options.
#            - ICMPv6 types.
#            - Expose bytefields for all descriptors.
#            - Unit-test more error conditions, and improve error reporting.
#            - Protocols:
#                - PPP
#                - PFSync
#                - Carp
#                - Routing protocols
#                - Higher-level protocols
#                - SLIP
#                - BOOTP
#            - More extensive testing. 
#                - Generalise all protocol unit-tests to take a packet argument to act on.
#                - Use generalised tests to exhaustively test the functionality of user-created packets.
#            - A warnings framework to warn users of possibly undesired
#              situations, eg. the construction of impossible packets, etc.
#            - A detailed "dump" function that outputs all information about a packet.
#            - Packet Captures Required:
#                ICMPv4
#                    - ICMPRouterAdvertisement
#                    - ICMPInformationRequest
#                    - ICMPInformationReply
#                    - ICMPRedirect
#                ICMPv6
#                    - ICMP6DestinationUnreachable
#                    - ICMP6PacketTooBig
#                    - ICMP6TimeExceeded
import array, sys
from utils import *
import _sysvar
from _packetDescriptors import *


class PacketPyError(Exception): pass
class DataBoundsError(Exception): pass

#
# An options object that maps names to protocol numbers from the most recent
# IANA "Assigned Numbers" RFC
#
ProtocolOptions = Options(
                                ICMP                        = 1,
                                IGMP                        = 2,
                                IP_IN_IP                    = 4,
                                TCP                         = 6,
                                UDP                         = 17,
                                IPv6                        = 41,
                                ROUTING_HEADER              = 43,
                                FRAGMENTATION_HEADER        = 44,
                                ESP                         = 50,
                                AH                          = 51,
                                ICMP6                       = 58,
                                NO_NEXT_HEADER              = 59,
                                DESTINATION_OPTIONS_HEADER  = 60
                        )


def createPacket(*headerClasses):
    size = 0
    for i in headerClasses:
        size += i._SIZEHINT
    p = Packet(headerClasses[0], "\0"*size, 0)
    p.protostack = headerClasses[0](p, 0, 0)

    currentProtocol = p.protostack
    for i in headerClasses[1:]:
        currentProtocol._addProtocol(i, currentProtocol._SIZEHINT, 0)
        currentProtocol = currentProtocol._next
    p._selfConstruct()
    return p
        

class Packet(object):
    """
        This class represents a single given packet. Protocols within the
        packet protocol structure can be accessed as follows:
            p["icmp"]               - Returns the FIRST protocol of type "icmp" in the stack.
            p["icmp"]["icmp"]       - Returns the SECOND protocol of type "icmp".
            p["ip"]["icmp"]         - Returns the first ICMP protocol after the first IP protocol.
        Or
            p.getProtoList()        - Returns a list of all protocols in the stack.
    """
    def __init__(self, klass, packet, _initialise = 1):
        """
            klass   :   A class representing the first protocol in the protocol stack
            packet  :   The packet._data as a string.
        """
        self._data = array.array("c", packet)
        self._klass = klass
        self.protostack = None
        if _initialise:
            self.initialise()

    def __getitem__(self, proto):
        return self.protostack[proto]

    def has_key(self, key):
        return self.protostack.has_key(key)

    def __len__(self):
        return len(self._data)

    def __repr__(self):
        out = []
        for i in self.getProtoList():
            s = repr(i)
            if s:
                out.append("[" + s + "]")
        return " ".join(out)

    def initialise(self):
        self.protostack = self._klass(self)

    def getProtoList(self):
        """
            Returns a list of all protocol objects in the stack. 
        """
        return self.protostack._getProtoList()

    def getRaw(self):
        """
            Return the raw packet data.
        """
        return self._data.tostring()

    def _fixChecksums(self):
        """
            Fix all protocol checksums for this packet. 
        """
        lst = self.getProtoList()
        lst.reverse()
        for i in lst:
            i._fixChecksums()

    def _fixDimensions(self):
        """
            Fix packet dimension fields. 
        """
        lst = self.getProtoList()
        for i in lst:
            i._fixDimensions()

    def finalise(self):
        self._fixDimensions()
        self._fixChecksums()

    def _selfConstruct(self):
        lst = self.getProtoList()
        for i in lst:
            i._selfConstruct()


class Protocol(object):
    """
        Derived classes must define the following:

        TYPE            The name of this protocol.
    """
    TYPE = "Protocol"
    def __init__(self, packet, offset=0, constructNext=1):
        """
            Packet initialisation. 
                packet      - An instance of the Packet class
                offset      - The byte offset of the start of this protocol
                construct  - Create the next protocol in the chain?
        """
        self.packet = packet
        self.offset = offset
        self._next = None
        self._prev = None
        self._printList = []
        if constructNext:
            self._constructNext()

    def __repr__(self):
        return self.TYPE

    def __getitem__(self, proto):
        h = self._getProtoListInclusive()
        for i in h:
            if i._isType(proto):
                return i
        raise KeyError, "No such protocol: %s."%proto

    def has_key(self, key):
        h = self._getProtoListInclusive()
        for i in h:
            if i._isType(key):
                return 1
        return 0

    def __len__(self):
        i = 0
        current = self
        while 1:
            i += 1
            if current._next:
                current = current._next
            else:
                break
        return i
        
    def _isType(self, name):
        """
            Is this protocol of type "name"? Used for dict-like acces from
            Packet.

            We inspect the inheritance tree of the class, and check the TYPE
            attribute of each one. This allows us to, for instance, refer to
            either "icmp" and "icmpechorequest".
        """
        for i in self.__class__.__mro__:
            if hasattr(i, "TYPE"):
                if i.TYPE.lower() == name.lower():
                    return 1
        return 0

    def _getByteField(self, frm, tlen):
        """
            Return a number of bytes relative to the start of the current
            protocol.
        """
        if (self.offset+frm+tlen) > len(self.packet):
            raise DataBoundsError, "Field beyond packet bounds."
        return self.packet._data[self.offset+frm:self.offset+frm+tlen].tostring()

    def _setByteField(self, frm, tlen, val):
        """
            Set a number of bytes relative to the start of the current
            protocol header.
        """
        self.packet._data[self.offset+frm:self.offset+frm+tlen] = array.array("c", val)

    def _getIntField(self, frm, tlen):
        """
            Return an integer corresponding to a whole number of bytes,
            relative to the start of the current protocol header.
        """
        return multiord(self._getByteField(frm, tlen))

    def _setIntField(self, frm, tlen, val):
        """
            Set a field of bits to an integer value. The bit field position is
            specified relative to the start of the current protocol header.
        """
        return self._setByteField(frm, tlen, multichar(val, tlen))

    def _getBitField(self, frm, bitoffset, bitlen):
        """
            Retrieve the integer value of a set of bits.
            byteoffset : offset in bytes of the first byte from the start of data.
            bitoffset  : offset in bits from byteoffset to the first bit.
            bitlen     : number of bits to be extracted.
        """
        byteLen, m = divmod(bitoffset + bitlen, 8)
        if m:
            byteLen = byteLen+1
        x = self._getIntField(frm, byteLen)
        # Clear the high bits:
        x = x&(pow(2, (byteLen*8 - bitoffset))-1)
        # Shift out the low bits:
        x = x>>(byteLen*8 - bitoffset - bitlen)
        return x

    def _setBitField(self, frm, bitoffset, bitlen, val):
        """
            Set the integer value of a set of bits.
            bitoffset : offset it bits from the start of the data.
            bitlen    : length of the bitfield to be set.
            val       : value to be written into place as an integer.
        """
        if 0 > val or val > (pow(2, bitlen)-1):
            raise ValueError, "Bit field must be in range 0-%s"%(pow(2, bitlen)-1)
        byteLen, m = divmod(bitoffset + bitlen, 8)
        if m:
            byteLen = byteLen+1
        val = val << (byteLen*8 - bitoffset - bitlen)
        old = self._getIntField(frm, byteLen)
        # Now we clear the corresponding bits in the old value
        mask = ~((pow(2, bitlen)-1) << (byteLen*8 - bitoffset - bitlen))
        old = old&mask
        self._setIntField(frm, byteLen, old|val)

    def _splice(self, frm, to, val):
        self.packet._data[self.offset+frm:self.offset+to] = array.array("c", val)
        self.packet.initialise()

    def _addProtocol(self, protocol, nextoffset, *args):
        p = protocol(self.packet, self.offset + nextoffset, *args)
        self._next = p
        p._prev = self

    def _getProtoList(self):
        x = self
        while x._prev:
            x = x._prev
        return x._getProtoListInclusive()

    def _getProtoListInclusive(self):
        current = self
        lst = []
        while 1:
            lst.append(current)
            if current._next:
                current = current._next
            else:
                break
        return lst

    def _getSizehint(self):
        """
            Retrieve the cumulative SIZEHINT for this protocol and all
            protocols it contains.
        """
        sizehint = 0
        for i in self._getProtoListInclusive():
            sizehint += i._SIZEHINT
        return sizehint

    def _fixDimensions(self):
        """
            The _fixDimensions method for each protocol adjusts offset and
            length fields to take accound of a possible change in payload
            length. This is done as follows:
                    - Take the difference between protocol.offset and the total
                      length of the packet. 
                    - Now subtract the expected length the protocol headers.
                    - This gives you the payload length. Adjust dimension
                      fields to suit.
        """
        pass

    def _fixChecksums(self):
        """
            Protocol checksum methods are called in reverse order. That is, if
            we have a packet [Ethernet][IP][TCP], the finalise method for TCP
            will be called first, then IP, then Ethernet.
        """
        return

    def _constructNext(self):
        """
            This method should be implemented for all protocols that can
            contain nested protocols. It should construct the next protocol in
            the chain, and will usually add it using the _addProtocol method.
        """
        pass

    def _selfConstruct(self):
        """
            This method performs the "self-construction" actions for a given
            protocol. It is called during the packet creation process, i.e.
            when packets are created from scratch. This method should:
                - Inspect the _next class, and set protocol identification
                  information accordingly.
                - Set sensible defaults (e.g. ttls, IP header version fields, etc.)
        """
        pass


def ipOptionFactory(parent, ipproto, offset):
    # We inspect the first byte of the Options to find the initial Option type.
    optionJmpTable = {
               _IPOption._TypeOptions["EndOfList"]:               IPOptionEndOfList,
               _IPOption._TypeOptions["NOP"]:                     IPOptionNOP,
               _IPOption._TypeOptions["Security"]:                IPOptionSecurity,
               _IPOption._TypeOptions["LooseSourceRouting"]:      IPOptionLooseSourceRouting,
               _IPOption._TypeOptions["StrictSourceRouting"]:     IPOptionStrictSourceRouting,
               _IPOption._TypeOptions["RecordRoute"]:             IPOptionRecordRoute,
               _IPOption._TypeOptions["StreamID"]:                IPOptionStreamID,
               _IPOption._TypeOptions["InternetTimestamp"]:       IPOptionInternetTimestamp,
    }
    opt = _IPOption(parent, ipproto, offset)
    if optionJmpTable.has_key(opt.optionType):
        return optionJmpTable[opt.optionType](parent, ipproto, offset)
    else:
        return None


class _IPOption(Protocol):
    _TypeOptions = Options(
               EndOfList            = 0x0,
               NOP                  = 0x1,
               Security             = 0x130,
               LooseSourceRouting   = 0x131,
               StrictSourceRouting  = 0x137,
               RecordRoute          = 0x7,
               StreamID             = 0x136,
               InternetTimestamp    = 0x138
    )
    optionType = IntField(0, 1, options=_TypeOptions)
    length = 1
    def __init__(self, parent, ipproto, offset):
        Protocol.__init__(self, parent, offset)
        self.ipproto = ipproto
        self._next = self._getNext()

    def _getNext(self):
        if not (self.offset > (self.ipproto.offset + (self.ipproto.headerLength * 4))):
            return ipOptionFactory(self.packet, self.ipproto, self.offset + self.length)
        else:
            return None

    def initialise(self):
        self.packet.initialise()


class IPOptionEndOfList(_IPOption):
    TYPE = "IPOptionEndOfList"
    def _getNext(self):
        return None


class IPOptionNOP(_IPOption):
    TYPE = "IPOptionNOP"


class _IPOptionExtended(_IPOption):
    """
        An IP Option that has an associated length.
    """
    length = IntField(1, 1)
    def __init__(self, *args):
        _IPOption.__init__(self, *args)

    
class IPOptionSecurity(_IPOptionExtended):
    TYPE = "IPOptionSecurity"
    payload = Payload()
    def _getPayloadOffsets(self):
        offset = 2
        dataLength = self.length
        return offset, dataLength


class _IPOptionRouting(_IPOptionExtended):
    pointer     = IntField(2, 1)
    addrlist    = DescriptorProxy("_addrlist")
    def __init__(self, *args):
        _IPOptionExtended.__init__(self, *args)
        self._addrlist = IPAddressList(3, self.length-3)


class IPOptionLooseSourceRouting(_IPOptionRouting):
    TYPE = "IPOptionLooseSourceRouting"


class IPOptionStrictSourceRouting(_IPOptionRouting):
    TYPE = "IPOptionStrictSourceRouting"


class IPOptionRecordRoute(_IPOptionRouting):
    TYPE = "IPOptionRecordRoute"


class IPOptionStreamID(_IPOptionExtended):
    TYPE = "IPOptionStreamID"
    payload = Payload()
    def _getPayloadOffsets(self):
        offset = 2
        dataLength = self.length
        return offset, dataLength


class IPOptionInternetTimestamp(_IPOptionExtended):
    TYPE = "IPOptionInternetTimestamp"
    _FlagsOptions = Options(
            TIMESTAMP_ONLY      = 0,
            IP_PRECEDES         = 1,
            IP_PRESPECIFIED     = 3
    )
    length      = IntField(2, 1)
    overflow    = BitField(3, 0, 4)
    flag        = FlagsField(3, 4, 4, options=_FlagsOptions)
    payload     = Payload()
    def _getPayloadOffsets(self):
        dataLength = self.length - 4
        return 4, dataLength


class IP(Protocol):
    TYPE = "IP"
    _SIZEHINT = 20
    _FlagsOptions = Options(
        MF     = 1,
        DF     = 2,
        RES    = 4    # Reserved bit
    )
    # Fields
    version         = BitField(0, 0, 4,     "IP Protocol Version")
    headerLength    = BitField(0, 4, 4,     "Length of IP Header in 32-bit words")
    tos             = IntField(1, 1,        "Type of Service")
    length          = IntField(2, 2,        "Length of packet in bytes, including payload")
    ident           = IntField(4, 2,        "IP identification number")
    flags           = FlagsField(6, 0, 3,   "IP Flags", options=_FlagsOptions)
    fragmentOffset  = BitField(6, 3, 13,    "Fragment Offset")
    ttl             = IntField(8, 1,        "Time to Live")
    protocol        = IntField(9, 1,        "Contained Protocol", options=ProtocolOptions)
    checksum        = IntField(10, 2,       "32-bit CRC")
    src             = IPAddress(12,         "Source IP Address")
    dst             = IPAddress(16,         "Destination IP Address")
    optionsField    = DescriptorProxy("_optionsField")
    # FIXME: header padding
    payload         = Payload()

    def __init__(self, *args):
        Protocol.__init__(self, *args)
        self._optionsField = ByteField(20, (self.headerLength*4) - 20)
        if self.optionsField:
            self.options = ipOptionFactory(self.packet, self, self.offset+20)

    def __repr__(self):
        return "IP: %s->%s"%(self.src, self.dst)

    def _getPayloadOffsets(self):
        offset = self.headerLength*4
        dataLength = self.length - offset
        return offset, dataLength

    def _selfConstruct(self):
        if self._next:
            # We make a horrid exception for ICMP - ICMP can be any of a number of classes...
            if isinstance(self._next, ICMPBase):
                self.protocol = "ICMP"
            else:
                self.protocol = IP4_PROTO_JUMPER.get(self._next.__class__, 0)
        self.headerLength = self._SIZEHINT/4
        self.length = self._getSizehint()
        self.version = 4
        self.ttl = 255

    def _constructNext(self):
        try:
            if IP4_PROTO_JUMPER.has_key(self.protocol):
                self._addProtocol(IP4_PROTO_JUMPER[self.protocol], self.headerLength*4)
        except DataBoundsError:
            # If our data length is too short, we simply don't consruct the
            # next proto...
            pass

    def _fixChecksums(self):
        self.checksum = 0
        self.checksum = cksum16(self.packet._data[self.offset:self.offset + (self.headerLength * 4)])

    def _fixDimensions(self):
        self.length = (len(self.packet) - self.offset)


class ICMPBase(Protocol):
    TYPE = "ICMP"
    _SIZEHINT = 4
    _TypeOptions = Options(
                            ICMPEchoReply                   = 0,
                            ICMPDestinationUnreachable      = 3,
                            ICMPSourceQuench                = 4,
                            ICMPRedirect                    = 5,
                            ICMPEchoRequest                 = 8,
                            ICMPRouterAdvertisement         = 9,
                            ICMPRouterSolicitation          = 10,
                            ICMPTimeExceeded                = 11,
                            ICMPParameterProblem            = 12,
                            ICMPTimestampRequest            = 13,
                            ICMPTimestampReply              = 14,
                            ICMPInformationRequest          = 15,
                            ICMPInformationReply            = 16,
                            ICMPAddressMaskRequest          = 17,
                            ICMPAddressMaskReply            = 18
                    )
    itype       = IntField(0, 1, "ICMP Type", _TypeOptions)
    code        = IntField(1, 1, "ICMP Code (See CODE_* attributes)")
    checksum    = IntField(2, 2, "CRC16 Checksum")
    payload     = Payload()
    def _fixChecksums(self):
        self.checksum = 0
        self.checksum = cksum16(self._prev.payload)

    def _selfConstruct(self):
        self.itype = self.TYPE

    def _getPayloadOffsets(self):
        offset = 8
        dataLength = self._prev.length - (self._prev.headerLength*4 + offset)
        return offset, dataLength


class _ICMPIDSeqBase(ICMPBase):
    """
        Base for ICMP packets that also have an ID and a sequence
        number.
    """
    _SIZEHINT = 8
    identifier = IntField(4, 2)
    seq_num = IntField(6, 2)


class _ICMPWithIPHdr(ICMPBase):
    """
        Base for ICMP packets that also have an appended IP header
    """
    _SIZEHINT = 8 + IP._SIZEHINT + 64
    def __init__(self, packet, offset=None, *args):
        ICMPBase.__init__(self, packet, offset, *args)
        self.iphdr = IP(packet, offset+8)


class ICMPDestinationUnreachable(_ICMPWithIPHdr):
    """
        ICMP Destination Unreachable

        See RFC 792
    """
    TYPE = "ICMPDestinationUnreachable"
    _CodeOptions = Options(
        NET_UNREACHABLE            = 0,
        HOST_UNREACHABLE           = 1,
        PROTOCOL_UNREACABLE        = 2,
        PORT_UNREACABLE            = 3,
        FRAG_NEEDED_DF_SET         = 4,
        SOURCE_ROUTE_FAILED        = 5
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    def __repr__(self):
        return "ICMP Destination Unreachable"


class ICMPSourceQuench(_ICMPWithIPHdr):
    """
        ICMP Source Quench
            gateway_addr    :   Gateway Address

        See RFC 792
    """
    TYPE = "ICMPSourceQuench"
    _CodeOptions = Options(
        SOURCE_QUENCH            = 0
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    def __repr__(self):
        return "ICMP Source Quench"


class ICMPRedirect(_ICMPWithIPHdr):
    """
        ICMP Redirect
            gateway_addr    :   Gateway Address
    """
    TYPE = "ICMPRedirect"
    _SIZEHINT = 8
    _CodeOptions = Options(
        NETWORK_REDIRECT           = 0,
        HOST_REDIRECT              = 1,
        TOS_NETWORK_REDIRECT       = 2,
        TOSHOST_REDIRECT           = 3
    )
    code            = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    gateway_addr    = IPAddress(4)
    def __repr__(self):
        return "ICMP Redirect"


class _ICMPEcho(_ICMPIDSeqBase):
    TYPE = "ICMPEcho"


class ICMPEchoRequest(_ICMPEcho):
    """
        ICMP Echo Request
            identifier  :   Identifier
            seq_num     :   Sequence Number
    """
    TYPE = "ICMPEchoRequest"
    _CodeOptions = Options(
        ECHO_REQUEST            = 0
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    def __repr__(self):
        return "ICMP Echo Request"


class ICMPEchoReply(_ICMPEcho):
    """
        ICMP Echo Reply
            identifier  :   Identifier
            seq_num     :   Sequence Number
    """
    TYPE = "ICMPEchoReply"
    _CodeOptions = Options(
        ECHO_REPLY            = 0
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    def __repr__(self):
        return "ICMP Echo Reply"


class ICMPRouterAdvertisement(ICMPBase):
    """
        ICMP Router Advertisement
            itype       :   Type of ICMP packet
            code        :   Code of more specific packet purpose 
            checksum    :   Checksum
    """
    TYPE = "ICMPRouterAdvertisement"
    _CodeOptions = Options(
        ROUTER_ADVERTISEMENT   = 0
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    num_addresses   = IntField(4, 1)
    address_size    = IntField(5, 1)
    def __repr__(self):
        return "ICMP Router Advertisement"
    

class ICMPRouterSolicitation(ICMPBase):
    """
        ICMP Router Solicitation
            itype       :   Type of ICMP packet
            code        :   Code of more specific packet purpose 
            checksum    :   Checksum
    """
    TYPE = "ICMPRouterSolicitation"
    _SIZEHINT = 8
    _CodeOptions = Options(
        ROUTER_SOLICITATION   = 0
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    num_addresses   = IntField(4, 1)
    address_size    = IntField(5, 1)
    lifetime        = IntField(6, 2)
    # FIXME The contained router addresses need to be
    # collected and mapped to an array for the user
    def __repr__(self):
        return "ICMP Router Solicitation"


class ICMPTimeExceeded(_ICMPWithIPHdr):
    """
        ICMP Time Exceeded
            gateway_addr    :   Gateway Address
    """
    TYPE = "ICMPTimeExceeded"
    _CodeOptions = Options(
        TRANSIT        = 0,
        REASSEMBLY     = 1
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    def __repr__(self):
        return "ICMP Time Exceeded"


class ICMPParameterProblem(_ICMPWithIPHdr):
    """
        ICMP Parameter Problem
            gateway_addr    :   Gateway Address
    """
    TYPE = "ICMPParameterProblem"
    _CodeOptions = Options(
        HEADER_BAD         = 0,
        OPTION_MISSING     = 1
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    pointer = IntField(4, 1)

    def __repr__(self):
        return "ICMP Parameter Problem"


class _ICMPTimestampBase(_ICMPIDSeqBase):
    """
        ICMP Timestamp Base
            identifier  :   Identifier
            seq_num     :   Sequence Number
    """
    _SIZEHINT = 20
    origin_ts   = IntField(8, 4)
    receive_ts  = IntField(12, 4)
    transmit_ts = IntField(16, 4)


class ICMPTimestampRequest(_ICMPTimestampBase):
    """
        ICMP Timestamp Request
            identifier      :   Identifier
            seq_num         :   Sequence Number
            origin_ts       :   Origin Timestamp
            receive_ts      :   Receiver Timestamp
            transmit_ts     :   Transmitting Timestamp
    """
    TYPE = "ICMPTimestampRequest"
    _CodeOptions = Options(
        TIMESTAMP_REQUEST  = 0
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)

    def __repr__(self):
        return "ICMP Timestamp Request"


class ICMPTimestampReply(_ICMPTimestampBase):
    """
        ICMP Timestamp Reply
            identifier      :   Identifier
            seq_num         :   Sequence Number
            origin_ts       :   Origin Timestamp
            receive_ts      :   Receiver Timestamp
            transmit_ts     :   Transmitting Timestamp
    """
    TYPE = "ICMPTimestampReply"
    _CodeOptions = Options(
        TIMESTAMP_REPLY    = 0
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)

    def __repr__(self):
        return "ICMP Timestamp Reply"


class ICMPInformationRequest(_ICMPIDSeqBase):
    """
        ICMP Information Request
            identifier      :   Identifier
            seq_num         :   Sequence Number
    """
    TYPE = "ICMPInformationRequest"
    _CodeOptions = Options(
        INFORMATION_REQUEST    = 0
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    def __repr__(self):
        return "ICMP Information Request"


class ICMPInformationReply(_ICMPIDSeqBase):
    """
        ICMP Information Reply
            identifier      :   Identifier
            seq_num         :   Sequence Number
    """
    TYPE = "ICMPInformationReply"
    _CodeOptions = Options(
        INFORMATION_REPLY    = 0
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    def __repr__(self):
        return "ICMP Information Reply"


class ICMPAddressMaskRequest(_ICMPIDSeqBase):
    """
        ICMP Address Mask Request
            identifier      :   Identifier
            seq_num         :   Sequence Number
    """
    TYPE = "ICMPAddressMarkRequest"
    _CodeOptions = Options(
        ADDRESSMASK_REQUEST    = 0
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    def __repr__(self):
        return "ICMP Address Mask Request"


class ICMPAddressMaskReply(_ICMPIDSeqBase):
    """
        ICMP Address Mask Reply
            identifier      :   Identifier
            seq_num         :   Sequence Number
    """
    _SIZEHINT = 12
    TYPE = "ICMPAddressMaskReply"
    _CodeOptions = Options(
        ADDRESSMASK_REPLY      = 0
    )
    code        = IntField(1, 1, "ICMP Code", options=_CodeOptions)
    subnet_mask = IPAddress(8)
    def __repr__(self):
        return "ICMP Address Mask Reply"


_ICMPJumptable = {
    ICMPBase._TypeOptions["ICMPECHOREPLY"]                   : ICMPEchoReply,
    ICMPBase._TypeOptions["ICMPECHOREQUEST"]                 : ICMPEchoRequest,
    ICMPBase._TypeOptions["ICMPDESTINATIONUNREACHABLE"]      : ICMPDestinationUnreachable,
    ICMPBase._TypeOptions["ICMPSOURCEQUENCH"]                : ICMPSourceQuench,
    ICMPBase._TypeOptions["ICMPREDIRECT"]                    : ICMPRedirect,
    ICMPBase._TypeOptions["ICMPECHOREQUEST"]                 : ICMPEchoRequest,
    ICMPBase._TypeOptions["ICMPROUTERADVERTISEMENT"]         : ICMPRouterAdvertisement,
    ICMPBase._TypeOptions["ICMPROUTERSOLICITATION"]          : ICMPRouterSolicitation,
    ICMPBase._TypeOptions["ICMPTIMEEXCEEDED"]                : ICMPTimeExceeded,
    ICMPBase._TypeOptions["ICMPPARAMETERPROBLEM"]            : ICMPParameterProblem,
    ICMPBase._TypeOptions["ICMPTIMESTAMPREQUEST"]            : ICMPTimestampRequest,
    ICMPBase._TypeOptions["ICMPTIMESTAMPREPLY"]              : ICMPTimestampReply,
    ICMPBase._TypeOptions["ICMPINFORMATIONREQUEST"]          : ICMPInformationRequest,
    ICMPBase._TypeOptions["ICMPINFORMATIONREPLY"]            : ICMPInformationReply,
    ICMPBase._TypeOptions["ICMPADDRESSMASKREQUEST"]          : ICMPAddressMaskRequest,
    ICMPBase._TypeOptions["ICMPADDRESSMASKREPLY"]            : ICMPAddressMaskReply
}
def ICMP(*args):
    """
        ICMP Factory Function.
    """
    stub = ICMPBase(*args)
    if _ICMPJumptable.has_key(stub.itype):
        return _ICMPJumptable[stub.itype](*args)
    else:
        return stub


class TCP(Protocol):
    """
        TCP
            Fields :
                srcPort     :   Source Port
                dstPort     :   Destination Port
                seq_num     :   Sequence Number
                ack_num     :   Ack Number
                dataOffset  :   Data Offset
                reserved    :   Reserved
                flags       :   Flags
                window      :   Window
                checksum    :   Checksum
                urgent      :   Urgent
    """
    TYPE = "TCP"
    _SIZEHINT = 20
    # Flags
    _FlagsOptions = Options(
        URG     = 32,
        ACK     = 16,
        PSH     = 8,
        RST     = 4,
        SYN     = 2,
        FIN     = 1
    )
    # Fields
    srcPort         = IntField(0, 2)
    dstPort         = IntField(2, 2)
    seq_num         = IntField(4, 4)
    ack_num         = IntField(8, 4)
    dataOffset      = BitField(12, 0, 4)
    reserved        = BitField(12, 4, 6)
    flags           = FlagsField(13, 2, 6, options=_FlagsOptions)
    window          = IntField(14, 2)
    checksum        = IntField(16, 2)
    # FIXME: TCP Options
    urgent          = IntField(18, 2)
    payload         = Payload()
    def _getPayloadOffsets(self):
        offset = self.dataOffset*4
        dataLength = self._prev.length - (self._prev.headerLength*4 + self.dataOffset*4)
        return offset, dataLength

    def _getPseudoHeader(self):
        ip = self._prev
        tcplen = self._getPayloadOffsets()
        tcplen = tcplen[0] + tcplen[1]
        phdr = [        ip._getByteField(12, 4),
                        ip._getByteField(16, 4),
                        "\0",
                        ip._getByteField(9, 1),
                        multichar(tcplen, 2)
                ]
        return array.array("c", "".join(phdr))

    def _fixChecksums(self):
        tcplen = self._getPayloadOffsets()
        tcplen = tcplen[0] + tcplen[1]
        self.checksum = 0
        self.checksum = cksum16(self._getPseudoHeader() + self.packet._data[self.offset:self.offset+tcplen])

    def _selfConstruct(self):
        self.dataOffset = 5

    def __repr__(self):
        return "TCP: %s->%s"%(self.srcPort, self.dstPort)


class UDP(Protocol):
    """
        UDP
            srcPort     :   Source Port
            dstPort     :   Destination Port
            length      :   Length
            checksum    :   Checksum
    """
    TYPE = "UDP"
    _SIZEHINT = 8
    srcPort     = IntField(0, 2)
    dstPort     = IntField(2, 2)
    length      = IntField(4, 2)
    checksum    = IntField(6, 2)
    payload     = Payload()
    def _getPayloadOffsets(self):
        offset = 8
        dataLength = self._prev.length - (self._prev.headerLength*4 + offset)
        return offset, dataLength

    def _getPseudoHeader(self):
        ip = self._prev
        phdr = [        ip._getByteField(12, 4),
                        ip._getByteField(16, 4),
                        "\0",
                        ip._getByteField(9, 1),
                        self._getByteField(4, 2)
                ]
        return array.array("c", "".join(phdr))

    def _fixChecksums(self):
        self.checksum = 0
        self.checksum = cksum16(self._getPseudoHeader() + \
                                self.packet._data[self.offset:self.offset+self.length])

    def __repr__(self):
        return "UDP: %s->%s"%(self.srcPort, self.dstPort)


class IGMP(Protocol):
    pass


class ARP(Protocol):
    """
        ARP
            Fields :
                hardware_type           :   Hardware Type
                protocol_type           :   Protocol Type
                hardware_size           :   Hardware Size
                protocol_size           :   Protocol Size
                opcode                  :   Op Code
                sender_hardware_addr    :   Sender Hardware Address
                sender_proto_addr       :   Sender Protocol Address
                target_hardware_addr    :   Target Hardware Address
                target_proto_addr       :   Target Protocol Address
    """
    # FIXME: We may want to split this into RARP and ARP classes.
    # FIXME: ARP is a strange case, in as much as its supposed to be
    # general accross hardware and protocol types, but in practice it
    # almost exclusively deals with Ethernet and IP. Perhaps we're letting a
    # foolish generality be the hobgoblin of our small minds here?
    TYPE = "ARP"
    _SIZEHINT = 28
    _OpcodeOptions = Options(
                            ARP_REQUEST     = 1,
                            ARP_REPLY       = 2,
                            RARP_REQUEST    = 3,
                            RARP_REPLY      = 4
                    )
    hardware_type    = IntField(0, 2)
    protocol_type    = IntField(2, 2)
    hardware_size    = IntField(4, 1)
    protocol_size    = IntField(5, 1)
    opcode           = IntField(6, 2, options = _OpcodeOptions)
    # We defer the choice of hardware and protocol descriptor types to the
    # instance.
    sender_hardware_addr    = DescriptorProxy("_sender_hardware_addr")
    sender_proto_addr       = DescriptorProxy("_sender_proto_addr")
    target_hardware_addr    = DescriptorProxy("_target_hardware_addr")
    target_proto_addr       = DescriptorProxy("_target_proto_addr")
    def __init__(self, *args):
        Protocol.__init__(self, *args)
        self._sender_hardware_addr    = EthernetAddress(8)
        self._target_hardware_addr    = EthernetAddress(18)

        self._sender_proto_addr       = IPAddress(14)
        self._target_proto_addr       = IPAddress(24)
    
    def _selfConstruct(self):
        self.hardware_type = 1
        self.protocol_type = 0x800 
        self.hardware_size = 6
        self.protocol_size = 4
        self.opcode = "arp_request"

    def __repr__(self):
        atype = self._OpcodeOptions.toStr(self.opcode)
        return "%s:  %s->%s"%(atype, self.sender_hardware_addr, self.target_hardware_addr)



class IPv6(Protocol):
    """
        IPv6
            version         :   Version
            diffservices    :   Differentiated Services
            flowlabel       :   Flow Label
            payloadlength   :   Payload Length
            nextheader      :   Next Header
            hoplimit        :   Hop Limit
            src             :   Source Address
            dst             :   Destination Address
    """
    TYPE = "IPv6"
    _SIZEHINT = 40
    # Protocols
    version         = BitField(0, 0, 4)
    diffservices    = BitField(0, 4, 8)
    flowlabel       = BitField(1, 4, 20)
    payloadlength   = IntField(4, 2)
    nextheader      = IntField(6, 1, options=ProtocolOptions)
    hoplimit        = IntField(7, 1)
    src             = IPv6Address(8)
    dst             = IPv6Address(24)
    payload         = Payload()

    def _selfConstruct(self):
        if self._next:
            # We make a horrid exception for ICMP6 - ICMP6 can be any of a number of classes...
            if isinstance(self._next, ICMP6Base):
                self.nextheader = "ICMP6"
            else:
                self.nextheader = IP6_PROTO_JUMPER.get(self._next.__class__, 0)
        self.version = 6
        self.hoplimit = 255
        self.diffservices = 0

    def _constructNext(self):
        try:
            if IP6_PROTO_JUMPER.has_key(self.nextheader):
                self._addProtocol(IP6_PROTO_JUMPER[self.nextheader], 40)
        except DataBoundsError:
            # If our data length is too short, we simply don't consruct the
            # next proto...
            pass

    def _getPayloadOffsets(self):
        return 40, self.payloadlength

    def __repr__(self):
        return "IPv6: %s->%s"%(self.src, self.dst)

    def _getPseudoHeader(self):
        phdr = [
                        self._getByteField(8, 16),
                        self._getByteField(24, 16),
                        utils.multichar(self.payloadlength, 4),
                        "\0\0\0", chr(58)
                ]
        return "".join(phdr)

    def _fixDimensions(self):
        self.payloadlength = len(self.packet) - self.offset - 40


class IPv6HopByHopHeader(Protocol):
    """
        IPv6 Hop by Hop Header
    """
    TYPE = "IPv6HopByHopHeader"
    _SIZEHINT = 2


class IPv6RoutingHeader(Protocol):
    """
        IPv6 Routing Header
    """
    TYPE = "IPv6RoutingHeader"
    _SIZEHINT = 2


class IPv6FragmentHeader(Protocol):
    """
        IPv6 Fragment Header
    """
    TYPE = "IPv6FragmentHeader"
    _SIZEHINT = 2


class IPv6DestinationOptionsHeader(Protocol):
    """
        IPv6 Destination Options Header
    """
    TYPE = "IPv6DestinationOptions"
    _SIZEHINT = 2


class AH(Protocol):
    """
        AH
    """
    TYPE = "AH"
    _SIZEHINT = 2
    nextheader          = IntField(0, 1, options=ProtocolOptions)
    length              = IntField(1, 1, "Length of the header in 32-bit words, minus 2")
    reserved            = IntField(2, 2)
    spi                 = IntField(4, 4)
    sequence            = IntField(8, 4)
    icv                 = DescriptorProxy("_icv")
    payload             = Payload()
    def __init__(self, *args):
        Protocol.__init__(self, *args)
        self._icv = ByteField(12, ((self.length + 2) * 4) - 12)

    def _getPayloadOffsets(self):
        offset = (self.length + 2) * 4
        dataLength = len(self.packet) - self.offset - offset
        return offset, dataLength

    def _constructNext(self):
        if IP6_PROTO_JUMPER.has_key(self.nextheader):
            self._addProtocol(IP6_PROTO_JUMPER[self.nextheader], 40)


class ESP(Protocol):
    """
        ESP
    """
    TYPE = "ESP"
    _SIZEHINT = 2
    spi             = IntField(0, 4)
    sequence        = IntField(4, 4)
    payload         = Payload()
    def _getPayloadOffsets(self):
        offset = 8
        dataLength = len(self._prev.payload) - 8
        return offset, dataLength


class ICMP6Base(Protocol):
    """
        Base Class for ICMP6
            Fields :
                icmp6type   :   Type of ICMP6 Packet
                code        :   Code for description of packet purpose
                checksum    :   Checksum
    """
    # FIXME: There are more types than just these.
    TYPE = "ICMP6"
    _SIZEHINT = 8
    _TypeOptions = Options(
                            DESTINATION_UNREACHABLE    = 1,
                            PACKET_TOO_BIG             = 2,
                            TIME_EXCEEDED              = 3,
                            PARAMETER_PROBLEM          = 4,
                            ECHO_REQUEST               = 128,
                            ECHO_REPLY                 = 129,
                            MULTICAST_LISTENER_QUERY   = 130,
                            MULTICAST_LISTENER_REPORT  = 131,
                            MULTICAST_LISTENER_DONE    = 132,
                            ROUTER_SOLICITATION        = 133,
                            ROUTER_ADVERTISEMENT       = 134,
                            NEIGHBOUR_SOLICITATION     = 135,
                            NEIGHBOUR_ADVERTISEMENT    = 136,
                            REDIRECT                   = 137,
                            ROUTER_RENUMBERING         = 138,
                            NODE_INFO_QUERY            = 139,
                            NODE_INFO_RESPONSE         = 140,
                            INVERSE_ND_SOLICITATION    = 141,
                            INVERSE_ND_ADV             = 142
                        )
    icmp6type       = IntField(0, 1, options=_TypeOptions)
    code            = IntField(1, 1)
    checksum        = IntField(2, 2)
    payload         = Payload()
    def _fixChecksums(self):
        self.checksum = 0
        self.checksum = cksum16(
                            self._prev._getPseudoHeader() +
                            self._prev.payload
                        )

    def _getPayloadOffsets(self):
        """
            The default implementation for ICMPv6 gives the entire message body
            as payload.
        """
        offset = 4
        dataLength = len(self.packet) - self.offset - 4
        return offset, dataLength


class ICMP6DestinationUnreachable(ICMP6Base):
    """
        ICMP6 Destination Unreachable
            icmp6type   :   Type of ICMP6 Packet
            code        :   Code for description of packet purpose
            checksum    :   Checksum
    """
    TYPE = "ICMP6DestinationUnreachable"
    unused          = ByteField(4, 4)
    def __init__(self, *args):
        ICMP6Base.__init__(self, *args)
        self.ip6hdr = IPv6(packet, offset+8)

    def __repr__(self):
        return "ICMPv6 Destination Unreachable"


class ICMP6PacketTooBig(ICMP6Base):
    """
        ICMP6 Packet Too Big
    """
    TYPE = "ICMP6PacketTooBig"
    mtu          = ByteField(4, 4)
    def __init__(self, *args):
        ICMP6Base.__init__(self, *args)
        self.ip6hdr = IPv6(packet, offset+8)

    def __repr__(self):
        return "ICMPv6 Packet Too Big"


class ICMP6TimeExceeded(ICMP6Base):
    """
        ICMP6 Time Exceeded
    """
    TYPE = "ICMP6TimeExceeded"
    unused          = ByteField(4, 4)
    def __init__(self, *args):
        ICMP6Base.__init__(self, *args)
        self.ip6hdr = IPv6(packet, offset+8)

    def __repr__(self):
        return "ICMPv6 Time Exceeded"


class ICMP6ParameterProblem(ICMP6Base):
    """
        ICMP6 Parameter Problem
    """
    TYPE = "ICMP6ParameterProblem"
    pointer         = IntField(4, 4)
    payload         = Payload()
    def __repr__(self):
        return "ICMPv6 Parameter Problem"


class _ICMP6EchoBase(ICMP6Base):
    """
        ICMP6 Echo Base Class
    """
    identifier = IntField(4, 2)
    seq_num = IntField(6, 2)
    def __init__(self, packet, offset):
        ICMP6Base.__init__(self, packet, offset)
        self.ip6hdr = IPv6(packet, offset+8)


class ICMP6EchoRequest(_ICMP6EchoBase):
    """
        ICMP6 Echo Request
            identifier  :   Identifier Number
            seq_num     :   Sequence Number
            ip6hdr      :   IPv6 Header
    """
    TYPE = "ICMP6EchoRequest"
    def __repr__(self):
        return "ICMPv6 Echo Request"


class ICMP6EchoReply(_ICMP6EchoBase):
    """
        ICMP6 Echo Reply
            identifier  :   Identifier Number
            seq_num     :   Sequence Number
            ip6hdr      :   IPv6 Header
    """
    TYPE = "ICMP6EchoReply"
    def __repr__(self):
        return "ICMPv6 Echo Reply"


class ICMP6NeighbourBase(ICMP6Base):
    """
        ICMP6 Neighbour Base Class
            target_addr     :   Target Address
            options         :   Contains a Link Layer Address
    """
    target_addr = IPv6Address(8)
    options = DescriptorProxy("_options_addr")
    def __init__(self, *args):
        Protocol.__init__(self, *args)
        # FIXME: Implement more hardware and protocol types. At the moment we
        # assume that we're talking about IPv6 over Ethernet.
        self._options_addr = EthernetAddress(26)


class ICMP6NeighbourSolicitation(ICMP6NeighbourBase):
    """
        ICMP6 Neighbour Solicitation
            target_addr     :   Target Address
            options         :   Contains a Link Layer Address
    """
    TYPE = "ICMP6NeighbourSolicitation"
    def __repr__(self):
        return "ICMPv6 Neighbour Solicitation"


class ICMP6NeighbourAdvertisement(ICMP6NeighbourBase):
    """
        ICMP6 Neighbour Advertisement
            target_addr     :   Target Address
            options         :   Contains a Link Layer Address
    """
    TYPE = "ICMP6NeighbourAdvertisement"
    _FlagsOptions = Options(
        OVERRIDE    = 1,
        SOLICITED   = 2,
        ROUTER      = 4
    )
    # Fields
    flags = FlagsField(4, 0, 3, options=_FlagsOptions)
    def __repr__(self):
        return "ICMPv6 Neighbour Advertisement"


_ICMP6Jumptable = {
    ICMP6Base._TypeOptions["DESTINATION_UNREACHABLE"]:           ICMP6DestinationUnreachable,
    ICMP6Base._TypeOptions["PACKET_TOO_BIG"]:                    ICMP6PacketTooBig,
    ICMP6Base._TypeOptions["TIME_EXCEEDED"]:                     ICMP6TimeExceeded,
    ICMP6Base._TypeOptions["PARAMETER_PROBLEM"]:                 ICMP6ParameterProblem,
    ICMP6Base._TypeOptions["ECHO_REQUEST"]:                      ICMP6EchoRequest,
    ICMP6Base._TypeOptions["ECHO_REPLY"]:                        ICMP6EchoReply,
    #ICMP6Base._TypeOptions["MULTICAST_LISTENER_QUERY"]:
    #ICMP6Base._TypeOptions["MULTICAST_LISTENER_REPORT"]:
    #ICMP6Base._TypeOptions["MULTICAST_LISTENER_DONE"]:
    #ICMP6Base._TypeOptions["ROUTER_SOLICITATION"]:
    #ICMP6Base._TypeOptions["ROUTER_ADVERTISEMENT"]:
    ICMP6Base._TypeOptions["NEIGHBOUR_SOLICITATION"]:            ICMP6NeighbourSolicitation,
    ICMP6Base._TypeOptions["NEIGHBOUR_ADVERTISEMENT"]:           ICMP6NeighbourAdvertisement,
    #ICMP6Base._TypeOptions["REDIRECT"]:
    #ICMP6Base._TypeOptions["ROUTER_RENUMBERING"]:
    #ICMP6Base._TypeOptions["NODE_INFO_QUERY"]:
    #ICMP6Base._TypeOptions["NODE_INFO_RESPONSE"]:
    #ICMP6Base._TypeOptions["INVERSE_ND_SOLICITATION"]:
    #ICMP6Base._TypeOptions["INVERSE_ND_ADV"]:
    #ICMP6Base._TypeOptions["INVERSE_ND_ADV"]:
}
def ICMP6(*args):
    """
        ICMP Factory Function.
    """
    stub = ICMP6Base(*args)
    if _ICMP6Jumptable.has_key(stub.icmp6type):
        return _ICMP6Jumptable[stub.icmp6type](*args)
    else:
        return stub


class Ethernet(Protocol):
    """
        Ethernet
            Fields :
                dst     :   Destination Address
                src     :   Source Address
                etype   :   Type of encapsulated protocol
                length  :   Length of packet
    """
    TYPE = "Ethernet"
    _SIZEHINT = 14
    TypeOptions = Options(
                            IP         = 0x800,
                            ARP        = 0x806,
                            RARP       = 0x8035,
                            IP6        = 0x86DD,
                            PPPOE      = 0x8864,
                            LOOPBACK   = 0x9000
                        )
    TYPE_JUMPER = DoubleAssociation(
        {
            TypeOptions["IP"]:        IP,
            TypeOptions["ARP"]:       ARP,
            TypeOptions["RARP"]:      ARP,
            TypeOptions["IP6"]:       IPv6,
        }
    )
    # Fields
    dst     =   EthernetAddress(0)
    src     =   EthernetAddress(6)
    etype   =   IntField(12, 2, options=TypeOptions)
    length  =   14
    payload = Payload()
    def _selfConstruct(self):
        if self._next:
            self.etype = self.TYPE_JUMPER.get(self._next.__class__, 0)

    def _constructNext(self):
        if self.TYPE_JUMPER.has_key(self.etype):
            self._addProtocol(self.TYPE_JUMPER[self.etype], self.length)

    def _getPayloadOffsets(self):
        return self.length, len(self.packet) - self.length

    def __repr__(self):
        return "Eth: %s->%s"%(self.src, self.dst)


class _PFBase(Protocol):
    """
        OpenBSD Specific.
        PF Logs.
    """
    TYPE="PF"
    # Reasons
    ReasonOptions = Options(
                            match       = _sysvar.PFRES_MATCH,
                            badoff      = _sysvar.PFRES_BADOFF,
                            frag        = _sysvar.PFRES_FRAG,
                            short       = _sysvar.PFRES_SHORT,
                            norm        = _sysvar.PFRES_NORM,
                            memory      = _sysvar.PFRES_MEMORY,
                            tstamp      = _sysvar.PFRES_TS,
                            congest     = _sysvar.PFRES_CONGEST,
                            ipoption    = _sysvar.PFRES_IPOPTIONS,
                            protocksum  = _sysvar.PFRES_PROTCKSUM,
                            state       = _sysvar.PFRES_BADSTATE,
                            stateins    = _sysvar.PFRES_STATEINS,
                            maxstates   = _sysvar.PFRES_MAXSTATES,
                            srclimit    = _sysvar.PFRES_SRCLIMIT,
                            synproxy    = _sysvar.PFRES_SYNPROXY
    )

    # Actions
    ActionOptions = Options(
                            drop              = _sysvar.PFACT_DROP,
                            scrub             = _sysvar.PFACT_SCRUB,
                            nat               = _sysvar.PFACT_NAT,
                            nonat             = _sysvar.PFACT_NONAT,
                            binat             = _sysvar.PFACT_BINAT,
                            nobinat           = _sysvar.PFACT_NOBINAT,
                            rdr               = _sysvar.PFACT_RDR,
                            nordr             = _sysvar.PFACT_NORDR,
                            synproxy_drop     = _sysvar.PFACT_SYNPROXY_DROP,
                            # Ugly magic used because "pass" is a Python keyword.
                        **{ "pass"          : _sysvar.PFACT_PASS}
    )
    # Directions
    DirectionOptions = Options(
                            inout           = _sysvar.PFDIR_INOUT,
                            out             = _sysvar.PFDIR_OUT,
                            # Ugly magic used because "in" is a Python keyword.
                        **{ "in"            : _sysvar.PFDIR_IN}
    )

    # SA Family Values
    SAFamilyOptions = Options(
                        UNSPEC       = 0,
                        LOCAL        = 1,
                        INET         = 2,
                        APPLETALK    = 16,
                        LINK         = 18,
                        INET6        = 24,
                        ENCAP        = 28
    )


class PFOld(_PFBase):
    TYPE = "PFOld"
    _SIZEHINT = _sysvar.IFNAMSIZ + 12
    # Fields
    safamily    =   IntField(0, 4, options=_PFBase.SAFamilyOptions)
    ifname      =   PaddedString(4, _sysvar.IFNAMSIZ)
    ruleno      =   IntField(4+_sysvar.IFNAMSIZ, 2)
    reason      =   IntField(4+_sysvar.IFNAMSIZ+2, 2, options=_PFBase.ReasonOptions)
    action      =   IntField(4+_sysvar.IFNAMSIZ+4, 2, options=_PFBase.ActionOptions)
    direction   =   IntField(4+_sysvar.IFNAMSIZ+6, 2, options=_PFBase.DirectionOptions)
    length      =   _sysvar.IFNAMSIZ + 12
    payload     =   Payload()
    def _constructNext(self):
        if AF_JUMPER.has_key(self.safamily):
            self._addProtocol(AF_JUMPER[self.safamily], self.length)

    def _getPayloadOffsets(self):
        offset = self.length
        dataLength = len(self.packet._data) - offset
        return offset, dataLength

    def __repr__(self):
        reason = self.ReasonOptions.toStr(self.reason)
        action = self.ActionOptions.toStr(self.action)
        direction = self.DirectionOptions.toStr(self.direction)
        return "Old PF rule %s (%s) %s %s on %s"%(self.ruleno, reason, action, direction, self.ifname)


class PF(_PFBase):
    """
        OpenBSD Specific : PF
    """
    _SIZEHINT = _sysvar.IFNAMSIZ + _sysvar.PF_RULESET_NAME_SIZE + 16
    TYPE = "PF"
    # Fields
    length      =   IntField(0, 1)  # Minus padding
    safamily    =   IntField(1, 1, options=_PFBase.SAFamilyOptions)
    action      =   IntField(2, 1, options=_PFBase.ActionOptions)
    reason      =   IntField(3, 1, options=_PFBase.ReasonOptions)
    ifname      =   PaddedString(4, _sysvar.IFNAMSIZ)
    ruleset     =   PaddedString(4 + _sysvar.IFNAMSIZ, _sysvar.PF_RULESET_NAME_SIZE)
    rulenr      =   IntField(4 + _sysvar.IFNAMSIZ + _sysvar.PF_RULESET_NAME_SIZE, 4)
    # Note: if subrulenumber == ((1L << 32) -1), there is no subrule. 
    subrulenr   =   IntField(8 + _sysvar.IFNAMSIZ + _sysvar.PF_RULESET_NAME_SIZE, 4)
    direction   =   IntField(12 + _sysvar.IFNAMSIZ + _sysvar.PF_RULESET_NAME_SIZE, 1,
                                                                options=_PFBase.DirectionOptions)
    pad         =   ByteField(13 + _sysvar.IFNAMSIZ + _sysvar.PF_RULESET_NAME_SIZE, 3)
    payload     =   Payload()
    def _constructNext(self):
        if AF_JUMPER.has_key(self.safamily):
            self._addProtocol(AF_JUMPER[self.safamily], self.length + 3)

    def _getPayloadOffsets(self):
        offset = self.length + 3
        dataLength = len(self.packet._data) - offset
        return offset, dataLength

    def __repr__(self):
        reason = self.ReasonOptions.toStr(self.reason)
        action = self.ActionOptions.toStr(self.action)
        direction = self.DirectionOptions.toStr(self.direction)
        if self.subrulenr == ((1L << 32) - 1):
            subrulenr = 0
        else:
            subrulenr = self.subrulenr
        return "PF rule %s/%s (%s) %s %s on %s"%(self.rulenr, subrulenr, reason, action, direction, self.ifname)


class Enc(Protocol):
    """
        OpenBSD Specific.
        Encapsulating Interface Protocol. 
    """
    _SIZEHINT = 12
    _FlagsOptions = Options(
               CONF         = 0x0400,
               AUTH         = 0x0800,
               AUTH_AH      = 0x2000
    )
    TYPE = "Enc"
    addressFamily       = HOInt32Field(0)
    spi                 = IntField(4, 4)
    flags               = HOInt32FlagsField(8, options=_FlagsOptions)
    def _constructNext(self):
        if AF_JUMPER.has_key(self.addressFamily):
            # See print_enc.c in tcpdump - it chickens out by simply assuming
            # that the next protocol in the chain is IP. We do the same,
            # because the address family and flags are stored in host byte
            # order, and we don't have any way of telling what "host byte
            # order" is from here if we're reading from a pcap dump file... 
            #self._addProtocol(AF_JUMPER[self.addressFamily], 12)
            self._addProtocol(AF_JUMPER[2], 12)

    def __repr__(self):
        options = []
        for i in self._FlagsOptions.keys():
            if self.flags & self._FlagsOptions[i]:
                options.append(i)
        return "Enc (%s)"%",".join(options)


class Loopback(Protocol):
    """
        The NULL header at the head of packets found on the loopback interface.
            length          :   Length
            addressFamily   :   Address Family
    """
    TYPE = "Loopback"
    _SIZEHINT = 4
    # AF Families
    AFOptions = Options(
                            UNSPEC       = 0,
                            LOCAL        = 1,
                            INET         = 2,
                            APPLETALK    = 16,
                            LINK         = 18,
                            INET6        = 24,
                            ENCAP        = 28
                        )
    # Fields
    length          = 4
    addressFamily   = IntField(0, 4, options=AFOptions)
    payload         = Payload()
    def _constructNext(self):
        if AF_JUMPER.has_key(self.addressFamily):
            self._addProtocol(AF_JUMPER[self.addressFamily], self.length)

    def _getPayloadOffsets(self):
        return self.length, len(self.packet) - self.length

    def _selfConstruct(self):
        self.addressFamily = AF_JUMPER.get(self._next.__class__, self.AFOptions["unspec"])

    def __repr__(self):
        # Intentionally returns an empty string. We don't normally want to know about loopback...
        return ""


AF_JUMPER = DoubleAssociation(
    {
        1:    Loopback,
        2:    IP,
        24:   IPv6,
    }

)

IP4_PROTO_JUMPER = DoubleAssociation(
    {
        ProtocolOptions["ICMP"]:      ICMP,
        ProtocolOptions["IGMP"]:      IGMP,
        ProtocolOptions["IP_IN_IP"]:  IP,
        ProtocolOptions["TCP"]:       TCP,
        ProtocolOptions["UDP"]:       UDP,
        ProtocolOptions["AH"]:        AH,
        ProtocolOptions["ESP"]:       ESP
    }
)

IP6_PROTO_JUMPER = DoubleAssociation(
    {
        ProtocolOptions["ICMP"]:                        ICMP,
        ProtocolOptions["IGMP"]:                        IGMP,
        ProtocolOptions["IP_IN_IP"]:                    IP,
        ProtocolOptions["TCP"]:                         TCP,
        ProtocolOptions["UDP"]:                         UDP,
        ProtocolOptions["IPv6"]:                        IPv6,
        ProtocolOptions["ROUTING_HEADER"]:              IPv6RoutingHeader,
        ProtocolOptions["FRAGMENTATION_HEADER"]:        IPv6FragmentHeader,
        ProtocolOptions["ESP"]:                         ESP,
        ProtocolOptions["AH"]:                          AH,
        ProtocolOptions["ICMP6"]:                       ICMP6,
        ProtocolOptions["DESTINATION_OPTIONS_HEADER"]:  IPv6DestinationOptionsHeader,
    }
)
