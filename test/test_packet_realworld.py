import sys
from packet.packet import *
import pcaptester
"""
    TODO
        
        - Cut the packet logs back to a single packet each.
"""
class uEthernet(pcaptester.pcapTester):
    dump = "tcp"
    def test_src(self):
        assert self.data["ethernet"].src == "00:09:6b:e0:ca:ce"
        self.data["ethernet"].src = "01:01:01:01:01:01"
        assert self.data["ethernet"].src == "01:01:01:01:01:01"

    def test_dst(self):
        assert self.data["ethernet"].dst == "00:02:b3:41:aa:c3"
        self.data["ethernet"].dst = "01:01:01:01:01:01"
        assert self.data["ethernet"].dst == "01:01:01:01:01:01"

    def test_etype(self):
        assert self.data["ethernet"].etype == 0x800
        self.data["ethernet"].etype = 0x888
        assert self.data["ethernet"].etype == 0x888

    def test_payload(self):
        assert self.data["ethernet"].payload
        self.data["ethernet"].payload = "asdf"
        assert self.data["ethernet"].payload == "asdf"

    def test_repr(self):
        repr(self.data)


class uTCP(pcaptester.pcapTester):
    dump = "tcp"
    def test_srcPort(self):
        assert self.data["tcp"].srcPort == 8012
        self.data["tcp"].srcPort = 8888
        assert self.data["tcp"].srcPort == 8888

    def test_dstPort(self):
        assert self.data["tcp"].dstPort == 22
        self.data["tcp"].dstPort = 8888
        assert self.data["tcp"].dstPort == 8888

    def test_seq_num(self):
        assert self.data["tcp"].seq_num == 1438057491
        self.data["tcp"].seq_num = 1111111111
        assert self.data["tcp"].seq_num == 1111111111

    def test_ack_num(self):
        assert self.data["tcp"].ack_num == 0
        self.data["tcp"].ack_num = 1111111111
        assert self.data["tcp"].ack_num == 1111111111

    def test_dataOffset(self):
        assert self.data["tcp"].dataOffset == 11
        self.data["tcp"].dataOffset = 12
        assert self.data["tcp"].dataOffset == 12

    def test_reserved(self):
        assert self.data["tcp"].reserved == 0
        self.data["tcp"].reserved = 8
        assert self.data["tcp"].reserved == 8

    def test_flags(self):
        assert self.data["tcp"].flags == 2
        self.data["tcp"].flags = 32
        assert self.data["tcp"].flags == 32

    def test_flagsoptions(self):
        assert self.data["tcp"].flags == TCP.flags["syn"]
        self.data["tcp"].flags = "rst"
        assert self.data["tcp"].flags == TCP.flags["rst"]

    def test_window(self):
        assert self.data["tcp"].window == 16384
        self.data["tcp"].window = 2323
        assert self.data["tcp"].window == 2323

    def test_checksum(self):
        assert self.data["tcp"].checksum == 0xca92
        cksum = self.data["tcp"].checksum
        self.data["tcp"].checksum = 2323
        assert self.data["tcp"].checksum == 2323
        self.data["tcp"]._fixChecksums()
        assert cksum == self.data["tcp"].checksum

    def test_urgent(self):
        assert self.data["tcp"].urgent == 0
        self.data["tcp"].urgent = 2323
        assert self.data["tcp"].urgent == 2323

    def test_payloadZero(self):
        assert len(self.data["tcp"].payload) == 0

    def test_payload(self):
        assert self.data["tcp"].payload == ""
        self.data["tcp"].payload = "asdf"
        self.data.finalise()
        assert self.data["tcp"].payload == "asdf"

    def test_emptyPayload(self):
        self.data["tcp"].payload = ""
        self.data.finalise()
        assert self.data["tcp"].payload == ""

    def test_repr(self):
        repr(self.data)


class uUDP(pcaptester.pcapTester):
    dump = "udp"    
    def test_srcPort(self):
        assert self.data["udp"].srcPort == 6739
        self.data["udp"].srcPort = 8888
        assert self.data["udp"].srcPort == 8888

    def test_dstPort(self):
        assert self.data["udp"].dstPort == 53
        self.data["udp"].dstPort = 8888
        assert self.data["udp"].dstPort == 8888

    def test_length(self):
        assert self.data["udp"].length == 31
        self.data["udp"].length = 8888
        assert self.data["udp"].length == 8888

    def test_checksum(self):
        assert self.data["udp"].checksum == 30925
        cksum = self.data["udp"].checksum
        self.data["udp"].checksum = 8888
        assert self.data["udp"].checksum == 8888
        self.data["udp"]._fixChecksums()
        assert cksum == self.data["udp"].checksum

    def test_payload(self):
        assert len(self.data["udp"].payload) == 23
        self.data["udp"].payload = "asdf"
        assert self.data["udp"].payload == "asdf"

    def test_payload(self):
        assert self.data["udp"].payload
        self.data["udp"].payload = "asdf"
        self.data.finalise()
        assert self.data["udp"].payload == "asdf"

    def test_repr(self):
        repr(self.data)


class uIP(pcaptester.pcapTester):
    dump = "icmp_echo_request"
    def test_version(self):
        assert self.data["ip"].version == 4
        self.data["ip"].version = 6
        assert self.data["ip"].version == 6

    def test_headerlength(self):
        assert self.data["ip"].headerLength == 5
        self.data["ip"].headerLength = 15
        assert self.data["ip"].headerLength == 15

    def test_tos(self):
        assert self.data["ip"].tos == 0
        self.data["ip"].tos = 4
        assert self.data["ip"].tos == 4

    def test_length(self):
        assert self.data["ip"].length == 84
        self.data["ip"].length = 100
        assert self.data["ip"].length == 100

    def test_ID(self):
        assert self.data["ip"].ident == 0x3fa8
        self.data["ip"].ident = 999
        assert self.data["ip"].ident == 999

    def test_flags(self):
        assert self.data["ip"].flags == 0
        self.data["ip"].flags = 1 
        assert self.data["ip"].flags == 1

    def test_flagsoptions(self):
        self.data["ip"].flags = "df"
        assert self.data["ip"].flags == IP.flags["DF"]

    def test_offset(self):
        assert self.data["ip"].fragmentOffset == 0
        self.data["ip"].fragmentOffset = 8000
        assert self.data["ip"].fragmentOffset == 8000

    def test_ttl(self):
        assert self.data["ip"].ttl == 64
        self.data["ip"].ttl = 200
        assert self.data["ip"].ttl == 200

    def test_protocol(self):
        assert self.data["ip"].protocol == 1
        self.data["ip"].protocol = 198
        assert self.data["ip"].protocol == 198

    def test_protocoloptions(self):
        assert self.data["ip"].protocol == ProtocolOptions["icmp"]
        self.data["ip"].protocol = "ah"
        assert self.data["ip"].protocol == ProtocolOptions["ah"]

    def test_checksum(self):
        assert self.data["ip"].checksum == 0x24ff
        cksum = self.data["ip"].checksum
        self.data["ip"].checksum = 21334
        assert self.data["ip"].checksum == 21334
        self.data["ip"]._fixChecksums()
        assert self.data["ip"].checksum == cksum

    def test_src(self):
        assert self.data["ip"].src == "10.0.1.1"
        self.data["ip"].src = "202.7.64.7"
        assert self.data["ip"].src == "202.7.64.7"

    def test_dst(self):
        assert self.data["ip"].dst == "10.0.1.2"
        self.data["ip"].dst = "202.7.64.7"
        assert self.data["ip"].dst == "202.7.64.7"

    def test_payload(self):
        assert len(str(self.data["ip"].payload)) == 64
        self.data["ip"].payload = "asdf"
        assert self.data["ip"].payload == "asdf"

    def test_payload(self):
        assert self.data["ip"].payload
        # Make sure the ICMP checksum doesn't stuff our payload.
        self.data["ip"].protocol = 61
        self.data["ip"].payload = "asdf"
        self.data.finalise()
        assert self.data["ip"].payload == "asdf"

    def test_options(self):
        assert not self.data["ip"].optionsField

    def test_repr(self):
        repr(self.data)


class uIPOptionsRecordRoute(pcaptester.pcapTester):
    dump = "ip_recordroute"
    pclass = Loopback
    def test_options(self):
        assert self.data["ip"].options["ipoptionrecordroute"]

    def test_length(self):
        assert self.data["ip"].options["ipoptionrecordroute"].length == 39
        self.data["ip"].options["ipoptionrecordroute"].length = 10
        assert self.data["ip"].options["ipoptionrecordroute"].length == 10

    def test_route(self):
        expected = [
                "0.255.255.255",
                "255.168.188.191",
                "207.140.188.191",
                "207.5.75.0",
                "28.1.0.0",
                "0.0.16.0",
                "0.236.188.191",
                "207.47.74.0",
                "28.0.0.0"
        ]
        assert self.data["ip"].options.addrlist == expected

    def test_nop(self):
        assert len(self.data["ip"].options) == 2
        assert self.data["ip"].options._next.TYPE == "IPOptionEndOfList"


##
# ICMP Test Cases
##
class uICMP(pcaptester.pcapTester):
    dump = "icmp_echo_request"
    def test_type(self):
        assert self.data["icmp"].itype == 8

    def test_checksum(self):
        assert self.data["icmp"].checksum == 0x4a5a
        cksum = self.data["icmp"].checksum
        self.data["icmp"].checksum = 50
        assert self.data["icmp"].checksum == 50
        self.data["icmp"]._fixChecksums()
        assert self.data["icmp"].checksum == cksum

    def test_payload(self):
        assert self.data["icmp"].payload
        self.data["icmp"].payload = "asdf"
        self.data.finalise()
        assert self.data["icmp"].payload == "asdf"

    def test_typeoptions(self):
        assert self.data["icmp"].itype == ICMPEchoRequest.itype["icmpechorequest"]
        self.data["icmp"].itype = "icmpechoreply"
        assert self.data["icmp"].itype == ICMPEchoRequest.itype["icmpechoreply"]

    def test_repr(self):
        repr(self.data)


class uICMP_DestinationUnreachable(pcaptester.pcapTester):
    dump = "icmp_unreachable"
    def test_iphdr(self):
        assert 4 == self.data["icmp"].iphdr.version
        assert "192.168.2.2" == self.data["icmp"].iphdr.src

    def test_checksum(self):
        assert self.data["icmp"].checksum == 0x17a5
        cksum = self.data["icmp"].checksum
        self.data["icmp"].checksum = 50
        assert self.data["icmp"].checksum == 50
        self.data["icmp"]._fixChecksums()
        assert self.data["icmp"].checksum == cksum

    def test_code(self):
        assert self.data["icmp"].code ==\
               ICMPDestinationUnreachable.code["HOST_UNREACHABLE"]

    def test_typeoptions(self):
        assert self.data["icmp"].itype ==\
               ICMPDestinationUnreachable.itype["icmpdestinationunreachable"]
        self.data["icmp"].itype = "icmpechoreply"
        assert self.data["icmp"].itype ==\
               ICMPDestinationUnreachable.itype["icmpechoreply"]

    def test_repr(self):
        repr(self.data)
        

class uICMP_EchoReply(pcaptester.pcapTester):
    dump = "icmp_echo_reply"
    def test_identifier(self):
        assert self.data["icmp"].identifier == 0x0511

    def test_seqNum(self):
        assert self.data["icmp"].seq_num == 0

    def test_checksum(self):
        assert self.data["icmp"].checksum == 0x745b
        cksum = self.data["icmp"].checksum
        self.data["icmp"].checksum = 50
        assert self.data["icmp"].checksum == 50
        self.data["icmp"]._fixChecksums()
        assert self.data["icmp"].checksum == cksum

    def test_code(self):
        assert self.data["icmp"].code == ICMPEchoReply.code["ECHO_REPLY"]

    def test_payload(self):
        assert len(self.data["icmp"].payload) == 56
        assert self.data["icmp"].payload[-8:] == "01234567"
        self.data["icmp"].payload = "ffff"
        self.data.finalise()
        assert self.data["icmp"].payload == "ffff"

    def test_typeoptions(self):
        assert self.data["icmp"].itype == ICMPEchoReply.itype["icmpechoreply"]
        self.data["icmp"].itype = "icmpechorequest"
        assert self.data["icmp"].itype == ICMPEchoReply.itype["icmpechorequest"]

    def test_repr(self):
        repr(self.data)



class uICMP_EchoRequest(pcaptester.pcapTester):
    dump = "icmp_echo_request"
    def test_identifier(self):
        assert self.data["icmp"].identifier == 0x050f

    def test_seqNum(self):
        assert self.data["icmp"].seq_num == 0x18

    def test_payload(self):
        assert len(self.data["icmp"].payload) == 56
        assert self.data["icmp"].payload[-8:] == "01234567"
        self.data["icmp"].payload = "asdf"
        self.data.finalise()
        assert self.data["icmp"].payload == "asdf"

    def test_checksum(self):
        assert self.data["icmp"].checksum == 0x4a5a
        cksum = self.data["icmp"].checksum
        self.data["icmp"].checksum = 50
        assert self.data["icmp"].checksum == 50
        self.data["icmp"]._fixChecksums()
        assert self.data["icmp"].checksum == cksum

    def test_code(self):
        assert self.data["icmp"].code ==  ICMPEchoRequest.code["ECHO_REQUEST"]

    def test_typeoptions(self):
        assert self.data["icmp"].itype ==  ICMPEchoRequest.itype["icmpechorequest"]
        self.data["icmp"].itype = "icmpechoreply"
        assert self.data["icmp"].itype ==  ICMPEchoRequest.itype["icmpechoreply"]

    def test_repr(self):
        repr(self.data)


class uICMP_RouterAdvertisement(pcaptester.pcapTester):
    pass

class uICMP_RouterSolicitation(pcaptester.pcapTester):
    pass

class uICMP_TimeExceeded(pcaptester.pcapTester):
    dump = "icmp_time_exceeded"
    def test_iphdr(self):
        assert self.data["icmp"].iphdr.version ==  4
        assert self.data["icmp"].iphdr.src ==  "192.168.0.2"

    def test_checksum(self):
        assert self.data["icmp"].checksum ==  0xd9ad
        cksum = self.data["icmp"].checksum
        self.data["icmp"].checksum = 50
        assert self.data["icmp"].checksum ==  50
        self.data["icmp"]._fixChecksums()
        assert self.data["icmp"].checksum ==  cksum

    def test_code(self):
        assert self.data["icmp"].code ==  ICMPTimeExceeded.code["TRANSIT"]

    def test_typeoptions(self):
        assert self.data["icmp"].itype ==  ICMPTimeExceeded.itype["icmptimeexceeded"]
        self.data["icmp"].itype = "icmpechoreply"
        assert self.data["icmp"].itype ==  ICMPTimeExceeded.itype["icmpechoreply"]

    def test_repr(self):
        repr(self.data)


class uICMP_TimestampRequest(pcaptester.pcapTester):
    dump = "icmp_timestamp_request"
    def test_values(self):
        assert self.data["icmp"].origin_ts ==  43666471
        assert self.data["icmp"].receive_ts ==  0
        assert self.data["icmp"].transmit_ts ==  0

    def test_checksum(self):
        assert self.data["icmp"].checksum ==  0xf11e
        cksum = self.data["icmp"].checksum
        self.data["icmp"].checksum = 50
        assert self.data["icmp"].checksum ==  50
        self.data["icmp"]._fixChecksums()
        assert self.data["icmp"].checksum ==  cksum

    def test_code(self):
        assert self.data["icmp"].code ==\
               ICMPTimestampRequest.code["TIMESTAMP_REQUEST"]

    def test_typeoptions(self):
        assert self.data["icmp"].itype ==  ICMPTimestampRequest.itype["icmptimestamprequest"]
        self.data["icmp"].itype = "icmpechoreply"
        assert self.data["icmp"].itype ==  ICMPTimestampRequest.itype["icmpechoreply"]

    def test_repr(self):
        repr(self.data)


class uICMP_TimestampReply(pcaptester.pcapTester):
    dump = "icmp_timestamp_reply"
    def test_stamps(self):
        assert self.data["icmp"].origin_ts ==  43702898
        assert self.data["icmp"].receive_ts ==  2685311235
        assert self.data["icmp"].transmit_ts ==  2685311235

    def test_checksum(self):
        assert self.data["icmp"].checksum ==  0xee7c
        cksum = self.data["icmp"].checksum
        self.data["icmp"].checksum = 50
        assert self.data["icmp"].checksum ==  50
        self.data["icmp"]._fixChecksums()
        assert self.data["icmp"].checksum ==  cksum

    def test_code(self):
        assert self.data["icmp"].code ==  ICMPTimestampReply.code["TIMESTAMP_REPLY"]

    def test_typeoptions(self):
        assert self.data["icmp"].itype ==  ICMPTimestampReply.itype["icmptimestampreply"]

    def test_repr(self):
        repr(self.data)


class uICMP_AddressMaskRequest(pcaptester.pcapTester):
    dump = "icmp_address_mask_request"
    def test_identifier(self):
        assert self.data["icmp"].identifier ==  0x134a

    def test_seqNum(self):
        assert self.data["icmp"].seq_num ==  0

    def test_checksum(self):
        assert self.data["icmp"].checksum ==  0xdbb5
        cksum = self.data["icmp"].checksum
        self.data["icmp"].checksum = 50
        assert self.data["icmp"].checksum ==  50
        self.data["icmp"]._fixChecksums()
        assert self.data["icmp"].checksum ==  cksum

    def test_code(self):
        assert self.data["icmp"].code ==  ICMPAddressMaskRequest.code["ADDRESSMASK_REQUEST"]

    def test_typeoptions(self):
        assert self.data["icmp"].itype ==  ICMPAddressMaskRequest.itype["icmpaddressmaskrequest"]

    def test_repr(self):
        repr(self.data)


class uICMP_AddressMaskReply(pcaptester.pcapTester):
    dump = "icmp_address_mask_reply"
    def test_identifier(self):
        assert self.data["icmp"].identifier ==  0x134a

    def test_seqNum(self):
        assert self.data["icmp"].seq_num ==  0

    def test_subnetMask(self):
        assert self.data["icmp"].subnet_mask ==  "255.255.0.0"

    def test_checksum(self):
        assert self.data["icmp"].checksum ==  0xdab5
        cksum = self.data["icmp"].checksum
        self.data["icmp"].checksum = 50
        assert self.data["icmp"].checksum ==  50
        self.data["icmp"]._fixChecksums()
        assert self.data["icmp"].checksum ==  cksum

    def test_code(self):
        assert self.data["icmp"].code ==  ICMPAddressMaskReply.code["ADDRESSMASK_REPLY"]

    def test_repr(self):
        repr(self.data)

    def test_typeoptions(self):
        assert self.data["icmp"].itype ==  ICMPAddressMaskReply.itype["icmpaddressmaskreply"]


if sys.byteorder == "little":
    # The Enc interface headers are in host byte-order. The sample dump is
    # taken on an i386 system, so we disable these tests on big-endian systems. 
    class uEnc(pcaptester.pcapTester):
        dump = "enc"
        def test_addressFamily(self):
            assert self.data["enc"].addressFamily ==  2
            self.data["enc"].addressFamily = 5
            assert self.data["enc"].addressFamily ==  5

        def test_spi(self):
            assert self.data["enc"].spi ==  0x10f2
            self.data["enc"].spi = 0xffff
            assert self.data["enc"].spi ==  0xffff

        def test_flags(self):
            assert self.data["enc"].flags ==  10240
            self.data["enc"].flags = 32
            assert self.data["enc"].flags ==  32

        def test_flagsoptions(self):
            assert self.data["enc"].flags & Enc.flags["auth"]
            self.data["enc"].flags = "auth_ah"
            assert self.data["enc"].flags ==  Enc.flags["auth_ah"]

        def test_nextproto(self):
            assert self.data.has_key("icmp")

        def test_repr(self):
            repr(self.data)

class uPfOld(pcaptester.pcapTester):
    dump = "pf.old"
    def test_safamily(self):
        p = self.data["pfold"]
        assert self.data["pfold"].safamily ==  self.data["pfold"].SAFamilyOptions["INET"]
        self.data["pfold"].safamily = 5
        assert self.data["pfold"].safamily ==  5

    def test_ifname(self):
        p = self.data["pfold"]
        assert self.data["pfold"].ifname ==  "tun0"
        self.data["pfold"].ifname = "bomb"
        assert self.data["pfold"].ifname ==  "bomb"

    def test_ruleno(self):
        p = self.data["pfold"]
        assert self.data["pfold"].ruleno ==  0
        self.data["pfold"].ruleno = 5
        assert self.data["pfold"].ruleno ==  5

    def test_reason(self):
        assert self.data["pfold"].reason ==  PFOld.ReasonOptions["MATCH"]
        self.data["pfold"].reason = 4
        assert self.data["pfold"].reason ==  4

    def test_action(self):
        assert self.data["pfold"].action ==  PFOld.ActionOptions["DROP"]
        self.data["pfold"].action = 5
        assert self.data["pfold"].action ==  5

    def test_direction(self):
        assert self.data["pfold"].direction ==  PFOld.DirectionOptions["IN"]
        self.data["pfold"].direction = 5
        assert self.data["pfold"].direction ==  5

    def test_encap(self):
        assert self.data["pfold"]._next.src ==  "68.18.67.181"

    def test_payload(self):
        assert self.data["pfold"].payload
        self.data["pfold"].safamily = self.data["pfold"].SAFamilyOptions["UNSPEC"]
        self.data["pfold"].payload = "asdf"
        self.data.finalise()
        assert self.data["pfold"].payload ==  "asdf"

    def test_repr(self):
        repr(self.data)


class uPf(pcaptester.pcapTester):
    dump = "pf"
    def test_length(self):
        assert self.data["pf"].length ==  45
        self.data["pf"].length = 5
        assert self.data["pf"].length ==  5

    def test_safamily(self):
        assert self.data["pf"].safamily ==  self.data["pf"].SAFamilyOptions["INET"]
        self.data["pf"].safamily = 5
        assert self.data["pf"].safamily ==  5

    def test_action(self):
        assert self.data["pf"].action ==  PF.ActionOptions["DROP"]
        self.data["pf"].action = 5
        assert self.data["pf"].action ==  5

    def test_reason(self):
        assert self.data["pf"].reason ==  PF.ReasonOptions["MATCH"]
        self.data["pf"].reason = 5
        assert self.data["pf"].reason ==  5

    def test_ifname(self):
        assert self.data["pf"].ifname ==  "lo0"
        self.data["pf"].ifname = "foo"
        assert self.data["pf"].ifname ==  "foo"

    def test_ruleset(self):
        assert self.data["pf"].ruleset ==  ""
        self.data["pf"].ruleset = "foo"
        assert self.data["pf"].ruleset ==  "foo"

    def test_rulenr(self):
        assert self.data["pf"].rulenr ==  1
        self.data["pf"].rulenr = 5
        assert self.data["pf"].rulenr ==  5

    def test_subrulenr(self):
        assert self.data["pf"].subrulenr ==  (1L << 32)-1
        self.data["pf"].subrulenr = 5
        assert self.data["pf"].subrulenr ==  5

    def test_direction(self):
        assert self.data["pf"].direction ==  PF.DirectionOptions["OUT"]
        self.data["pf"].direction = 3
        assert self.data["pf"].direction ==  3

    def test_pad(self):
        assert self.data["pf"].pad ==  "\0\0\0"
        self.data["pf"].pad = "xxx"
        assert self.data["pf"].pad ==  "xxx"
    
    def test_next(self):
        assert self.data["pf"]._next.src ==  "127.0.0.1"

    def test_payload(self):
        assert self.data["pf"].payload[:5] ==  "E\x00\x00T\xf1"
        self.data["pf"].safamily = self.data["pf"].SAFamilyOptions["UNSPEC"]
        self.data["pf"].payload = "asdf"
        self.data.finalise()
        assert self.data["pf"].payload ==  "asdf"

    def test_repr(self):
        repr(self.data)


class uLoopBack(pcaptester.pcapTester):
    dump = "ip_recordroute"
    def test_addressFamily(self):
        assert self.data["Loopback"].addressFamily == 2
        self.data["Loopback"].addressFamily = 3
        assert self.data["Loopback"].addressFamily == 3

    def test_addressFamilyOptions(self):
        assert self.data["Loopback"].addressFamily == self.data["Loopback"].AFOptions["inet"]
        self.data["Loopback"].addressFamily = "link"
        assert self.data["Loopback"].addressFamily == self.data["Loopback"].AFOptions["link"]

    def test_getProtoList(self):
        protos = self.data.protostack._getProtoList()
        assert protos ==  protos[0]._getProtoList()
        assert protos ==  protos[1]._getProtoList()
        assert protos ==  protos[2]._getProtoList()

    def test_getProtoListInclusive(self):
        names = [i.TYPE for i in self.data.getProtoList()]
        assert names, ["Loopback", "IP" ==  "ICMPEchoRequest"]

    def test_payload(self):
        assert self.data["loopback"].payload
        self.data["loopback"].payload = "asdf"
        assert self.data["loopback"].payload ==  "asdf"

    def test_repr(self):
        repr(self.data)



class uIPv6(pcaptester.pcapTester):
    dump = "icmp6_neighbor_sol"
    def test_version(self):
        assert self.data["ipv6"].version ==  6
        self.data["ipv6"].version = 10
        assert self.data["ipv6"].version ==  10

    def test_diffservices(self):
        assert self.data["ipv6"].diffservices ==  0
        self.data["ipv6"].diffservices = 10
        assert self.data["ipv6"].diffservices ==  10

    def test_flowlabel(self):
        assert self.data["ipv6"].flowlabel ==  0
        self.data["ipv6"].flowlabel = 10
        assert self.data["ipv6"].flowlabel ==  10

    def test_payloadlength(self):
        assert self.data["ipv6"].payloadlength ==  32
        self.data["ipv6"].payloadlength = 30
        assert self.data["ipv6"].payloadlength ==  30

    def test_nextheader(self):
        assert self.data["ipv6"].nextheader ==  0x3a
        self.data["ipv6"].nextheader = 30
        assert self.data["ipv6"].nextheader ==  30

    def test_nextheaderOptions(self):
        assert self.data["ipv6"].nextheader ==  ProtocolOptions["icmp6"]
        self.data["ipv6"].nextheader = "esp"
        assert self.data["ipv6"].nextheader ==  ProtocolOptions["esp"]

    def test_hoplimit(self):
        assert self.data["ipv6"].hoplimit ==  255
        self.data["ipv6"].hoplimit = 30
        assert self.data["ipv6"].hoplimit ==  30

    def test_src(self):
        assert self.data["ipv6"].src ==  "fe80::205:3cff:fe04:c8cf"
        self.data["ipv6"].src = "fe80:0:0:0:ffff:ffff:aaaa:2222"
        assert self.data["ipv6"].src ==  "fe80::ffff:ffff:aaaa:2222"

    def test_dst(self):
        assert self.data["ipv6"].dst ==  "ff02::1:ff68:5b6e"
        self.data["ipv6"].dst = "fe80:0:0:0:ffff:ffff:aaaa:2222"
        assert self.data["ipv6"].dst ==  "fe80::ffff:ffff:aaaa:2222"

    def test_payload(self):
        assert len(str(self.data["ipv6"].payload)) ==  self.data["ipv6"].payloadlength
        self.data["ipv6"].payload = "adsffff"
        self.data.finalise()
        assert self.data["ipv6"].payload, "asdffff"

    def test_repr(self):
        repr(self.data)

##
# ICMP6 Test Cases
##
class uICMP6(pcaptester.pcapTester):
    dump = "icmp6_neighbor_sol"
    def test_icmp6type(self):
        assert self.data["icmp6"].icmp6type ==  135
        self.data["icmp6"].icmp6type = 20
        assert self.data["icmp6"].icmp6type ==  20

    def test_icmp6typeOptions(self):
        assert self.data["icmp6"].icmp6type ==\
               ICMP6NeighbourSolicitation.icmp6type["neighbour_solicitation"]
        self.data["icmp6"].icmp6type = "echo_reply"
        assert self.data["icmp6"].icmp6type ==\
               ICMP6NeighbourSolicitation.icmp6type["echo_reply"]

    def test_code(self):
        assert self.data["icmp6"].code ==  0
        self.data["icmp6"].code = 20
        assert self.data["icmp6"].code ==  20

    def test_checksum(self):
        assert self.data["icmp6"].checksum ==  0x5e35
        self.data["icmp6"].checksum = 20
        assert self.data["icmp6"].checksum ==  20
        self.data["icmp6"]._fixChecksums()
        assert self.data["icmp6"].checksum ==  0x5e35

    def test_repr(self):
        repr(self.data)



class uICMP6_EchoRequest(pcaptester.pcapTester):
    dump = "icmp6_echorequest"
    def test_icmp6type(self):
        assert self.data["icmp6"].icmp6type ==  128
        self.data["icmp6"].icmp6type = 20
        assert self.data["icmp6"].icmp6type ==  20

    def test_icmp6typeOptions(self):
        assert self.data["icmp6"].icmp6type ==\
               ICMP6EchoRequest.icmp6type["echo_request"]
        self.data["icmp6"].icmp6type = "echo_reply"
        assert self.data["icmp6"].icmp6type ==\
               ICMP6EchoRequest.icmp6type["echo_reply"]

    def test_code(self):
        assert self.data["icmp6"].code ==  0
        self.data["icmp6"].code = 20
        assert self.data["icmp6"].code ==  20

    def test_checksum(self):
        assert self.data["icmp6"].checksum ==  0xabeb
        self.data["icmp6"].checksum = 20
        assert self.data["icmp6"].checksum ==  20

    def test_identifier(self):
        assert self.data["icmp6"].identifier ==  0x6a1e
        self.data["icmp6"].identifier = 20
        assert self.data["icmp6"].identifier ==  20

    def test_seqnum(self):
        assert self.data["icmp6"].seq_num ==  0x0000
        self.data["icmp6"].seq_num = 20
        assert self.data["icmp6"].seq_num ==  20

    def test_repr(self):
        repr(self.data)


class uICMP6_EchoReply(pcaptester.pcapTester):
    dump = "icmp6_echoreply"
    def test_icmp6type(self):
        assert self.data["icmp6"].icmp6type ==  129
        self.data["icmp6"].icmp6type = 20
        assert self.data["icmp6"].icmp6type ==  20

    def test_icmp6typeOptions(self):
        assert self.data["icmp6"].icmp6type ==\
               ICMP6EchoReply.icmp6type["echo_reply"]
        self.data["icmp6"].icmp6type = "echo_request"
        assert self.data["icmp6"].icmp6type ==\
               ICMP6EchoReply.icmp6type["echo_request"]

    def test_code(self):
        assert self.data["icmp6"].code ==  0
        self.data["icmp6"].code = 20
        assert self.data["icmp6"].code ==  20

    def test_checksum(self):
        assert self.data["icmp6"].checksum ==  0x0d89
        self.data["icmp6"].checksum = 20
        assert self.data["icmp6"].checksum ==  20

    def test_identifier(self):
        assert self.data["icmp6"].identifier ==  0x2e2e
        self.data["icmp6"].identifier = 20
        assert self.data["icmp6"].identifier ==  20

    def test_seqnum(self):
        assert self.data["icmp6"].seq_num ==  0x0000
        self.data["icmp6"].seq_num = 20
        assert self.data["icmp6"].seq_num ==  20

    def test_repr(self):
        repr(self.data)


class uICMP6_NeighborSolicitation(pcaptester.pcapTester):
    dump = "icmp6_neighbor_sol"
    def test_icmp6type(self):
        assert self.data["icmp6"].icmp6type ==  135
        self.data["icmp6"].icmp6type = 20
        assert self.data["icmp6"].icmp6type ==  20

    def test_icmp6typeOptions(self):
        assert self.data["icmp6"].icmp6type ==\
               ICMP6NeighbourSolicitation.icmp6type["neighbour_solicitation"]
        self.data["icmp6"].icmp6type = "echo_request"
        assert self.data["icmp6"].icmp6type ==\
               ICMP6NeighbourSolicitation.icmp6type["echo_request"]

    def test_code(self):
        assert self.data["icmp6"].code ==  0
        self.data["icmp6"].code = 20
        assert self.data["icmp6"].code ==  20

    def test_checksum(self):
        assert self.data["icmp6"].checksum ==  0x5e35
        self.data["icmp6"].checksum = 20
        assert self.data["icmp6"].checksum ==  20

    def test_targetAddress(self):
        assert self.data["icmp6"].target_addr ==  "fe80::209:5bff:fe68:5b6e"
        self.data["icmp6"].target_addr = "fe80:0:0:0:ffff:ffff:aaaa:2222"
        assert self.data["icmp6"].target_addr ==  "fe80::ffff:ffff:aaaa:2222"

    def test_optionsAddress(self):
        assert self.data["icmp6"].options ==  "00:05:3c:04:c8:cf"
        self.data["icmp6"].options = "00:05:3c:04:fa:fa"
        assert self.data["icmp6"].options ==  "00:05:3c:04:fa:fa"

    def test_repr(self):
        repr(self.data)


class uICMP6_NeighborAdvertisement(pcaptester.pcapTester):
    dump = "icmp6_neighbor_advertisement"
    def test_icmp6type(self):
        assert self.data["icmp6"].icmp6type ==  136
        self.data["icmp6"].icmp6type = 20
        assert self.data["icmp6"].icmp6type ==  20

    def test_icmp6typeOptions(self):
        assert self.data["icmp6"].icmp6type ==\
               ICMP6NeighbourSolicitation.icmp6type["neighbour_advertisement"]
        self.data["icmp6"].icmp6type = "echo_request"
        assert self.data["icmp6"].icmp6type ==\
               ICMP6NeighbourAdvertisement.icmp6type["echo_request"]

    def test_code(self):
        assert self.data["icmp6"].code ==  0
        self.data["icmp6"].code = 20
        assert self.data["icmp6"].code ==  20

    def test_checksum(self):
        assert self.data["icmp6"].checksum ==  0x5cf8
        self.data["icmp6"].checksum = 20
        assert self.data["icmp6"].checksum ==  20

    def test_targetAddress(self):
        assert self.data["icmp6"].target_addr ==  "fe80::2e0:29ff:fe94:495d"
        self.data["icmp6"].target_addr = "fe80:0:0:0:ffff:ffff:aaaa:2222"
        assert self.data["icmp6"].target_addr ==  "fe80::ffff:ffff:aaaa:2222"

    def test_optionsAddress(self):
        assert self.data["icmp6"].options ==  "00:e0:29:94:49:5d"
        self.data["icmp6"].options = "00:05:3c:04:fa:fa"
        assert self.data["icmp6"].options ==  "00:05:3c:04:fa:fa"
        
    def test_flags(self):
        assert self.data["icmp6"].flags ==  3
        opts = ICMP6NeighbourAdvertisement.flags
        self.data["icmp6"].flags =     opts["ROUTER"] |\
                                    opts["SOLICITED"] |\
                                    opts["OVERRIDE"]
        assert self.data["icmp6"].flags ==  7

    def test_flagsoptions(self):
        assert self.data["icmp6"].flags ==\
               (ICMP6NeighbourAdvertisement.flags["OVERRIDE"] |\
                ICMP6NeighbourAdvertisement.flags["SOLICITED"])
        self.data["icmp6"].flags = ("router", "solicited", "override")
        assert self.data["icmp6"].flags ==  7

    def test_repr(self):
        repr(self.data)

class uICMP6_ParameterProblem(pcaptester.pcapTester):
    dump = "icmp6_parameter_problem"
    pclass = Loopback
    def test_icmp6type(self):
        assert self.data["icmp6"].icmp6type ==  4
        self.data["icmp6"].icmp6type = 20
        assert self.data["icmp6"].icmp6type ==  20

    def test_icmp6typeOptions(self):
        assert self.data["icmp6"].icmp6type ==\
               ICMP6ParameterProblem.icmp6type["parameter_problem"]
        self.data["icmp6"].icmp6type = "echo_request"
        assert self.data["icmp6"].icmp6type ==\
               ICMP6ParameterProblem.icmp6type["echo_request"]

    def test_code(self):
        assert self.data["icmp6"].code ==  0
        self.data["icmp6"].code = 20
        assert self.data["icmp6"].code ==  20

    def test_checksum(self):
        assert self.data["icmp6"].checksum ==  0xe93e
        self.data["icmp6"].checksum = 20
        assert self.data["icmp6"].checksum ==  20

    def test_pointer(self):
        assert self.data["icmp6"].pointer ==  0x002c
        self.data["icmp6"].pointer = 0x003c
        assert self.data["icmp6"].pointer ==  0x003c

    def test_repr(self):
        repr(self.data)

class uARP(pcaptester.pcapTester):
    dump = "arprequest"
    def test_hardware_type(self):
        assert self.data["arp"].hardware_type ==  1

    def test_protocol_type(self):
        assert self.data["arp"].protocol_type ==  0x800

    def test_hardware_size(self):
        assert self.data["arp"].hardware_size ==  6

    def test_protocol_size(self):
        assert self.data["arp"].hardware_size ==  6

    def test_opcode(self):
        assert self.data["arp"].opcode ==  1

    def test_opcodeoptions(self):
        assert self.data["arp"].opcode ==\
               ARP.opcode["arp_request"]
        self.data["arp"].opcode = "rarp_request"
        assert self.data["arp"].opcode ==\
               ARP.opcode["rarp_request"]

    def test_sender_hardware_addr(self):
        assert self.data["arp"].sender_hardware_addr ==  "00:e0:7d:d4:60:ba"
        self.data["arp"].sender_hardware_addr = "00:e0:7d:d4:fa:fa"
        assert self.data["arp"].sender_hardware_addr ==  "00:e0:7d:d4:fa:fa"

    def test_sender_proto_addr(self):
        assert self.data["arp"].sender_proto_addr ==  "192.168.0.2"
        self.data["arp"].sender_proto_addr = "192.168.1.1"
        assert self.data["arp"].sender_proto_addr ==  "192.168.1.1"

    def test_target_hardware_addr(self):
        assert self.data["arp"].target_hardware_addr ==  "00:00:00:00:00:00"
        self.data["arp"].target_hardware_addr = "00:e0:7d:d4:fa:fa"
        assert self.data["arp"].target_hardware_addr ==  "00:e0:7d:d4:fa:fa"

    def test_target_proto_addr(self):
        assert self.data["arp"].target_proto_addr ==  "192.168.0.20"
        self.data["arp"].target_proto_addr = "192.168.1.1"
        assert self.data["arp"].target_proto_addr ==  "192.168.1.1"

    def test_repr(self):
        repr(self.data)


class uIPESP(pcaptester.pcapTester):
    dump = "ip_esp"
    def test_proto(self):
        assert self.data.has_key("esp")

    def test_spi(self):
        assert self.data["esp"].spi ==  0x100a
        self.data["esp"].spi = 0xfff
        assert self.data["esp"].spi ==  0xfff

    def test_sequence(self):
        assert self.data["esp"].sequence ==  1
        self.data["esp"].sequence = 12
        assert self.data["esp"].sequence ==  12

    def test_payload(self):
        self.data["esp"].payload


class uIPAH(pcaptester.pcapTester):
    dump = "ip_ah"
    def test_nextheader(self):
        assert self.data["ah"].nextheader ==  0x01
        self.data["ah"].nextheader = "IGMP"
        assert self.data["ah"].nextheader ==  0x02

    def test_length(self):
        assert self.data["ah"].length ==  4
        self.data["ah"].length = 18
        assert self.data["ah"].length ==  18

    def test_reserved(self):
        assert self.data["ah"].reserved ==  0
        self.data["ah"].reserved = 18
        assert self.data["ah"].reserved ==  18

    def test_spi(self):
        assert self.data["ah"].spi ==  0x10f2
        self.data["ah"].spi = 18
        assert self.data["ah"].spi ==  18

    def test_sequence(self):
        assert self.data["ah"].sequence ==  2759484411
        self.data["ah"].sequence = 18
        assert self.data["ah"].sequence ==  18

    def test_payload(self):
        assert self.data["ah"].payload.startswith("\x08\x00")

    def test_icv(self):
        assert self.data["ah"].icv.startswith("\x48\xc4")
        assert self.data["ah"].icv.endswith("\x27\xcb")

    def test_nextheader(self):
        assert self.data.has_key("icmp")


tests = [
    uEthernet(),
    uTCP(),
    uIP(),
    uIPOptionsRecordRoute(),
    uICMP(),
    uICMP_DestinationUnreachable(),
    uICMP_EchoReply(),
    uICMP_EchoRequest(),
    uICMP_RouterAdvertisement(),
    uICMP_RouterSolicitation(),
    uICMP_TimeExceeded(),
    uICMP_TimestampRequest(),
    uICMP_TimestampReply(),
    uICMP_AddressMaskRequest(),
    uICMP_AddressMaskReply(),
    uPfOld(),
    uPf(),
    uLoopBack(),
    uIPv6(),
    uICMP6(),
    uICMP6_EchoRequest(),
    uICMP6_EchoReply(),
    uICMP6_NeighborSolicitation(),
    uICMP6_NeighborAdvertisement(),
    uICMP6_ParameterProblem(),
    uARP(),
    uIPESP(),
    uIPAH(),
]
