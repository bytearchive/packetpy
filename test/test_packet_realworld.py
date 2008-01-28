import sys
from packet.packet import *
import pcaptester
"""
    TODO
        
        - Cut the packet logs back to a single packet each.
"""
class uEthernet(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("tcp")

    def test_src(self):
        self.failUnlessEqual(self.p["ethernet"].src, "00:09:6b:e0:ca:ce")
        self.p["ethernet"].src = "01:01:01:01:01:01"
        self.failUnlessEqual(self.p["ethernet"].src, "01:01:01:01:01:01")

    def test_dst(self):
        self.failUnlessEqual(self.p["ethernet"].dst, "00:02:b3:41:aa:c3")
        self.p["ethernet"].dst = "01:01:01:01:01:01"
        self.failUnlessEqual(self.p["ethernet"].dst, "01:01:01:01:01:01")

    def test_etype(self):
        self.failUnlessEqual(self.p["ethernet"].etype, 0x800)
        self.p["ethernet"].etype = 0x888
        self.failUnlessEqual(self.p["ethernet"].etype, 0x888)

    def test_payload(self):
        self.failUnless(self.p["ethernet"].payload)
        self.p["ethernet"].payload = "asdf"
        self.failUnlessEqual(self.p["ethernet"].payload, "asdf")

    def test_repr(self):
        repr(self.p)


class uTCP(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("tcp")

    def test_srcPort(self):
        self.failUnlessEqual(self.p["tcp"].srcPort, 8012)
        self.p["tcp"].srcPort = 8888
        self.failUnlessEqual(self.p["tcp"].srcPort, 8888)

    def test_dstPort(self):
        self.failUnlessEqual(self.p["tcp"].dstPort, 22)
        self.p["tcp"].dstPort = 8888
        self.failUnlessEqual(self.p["tcp"].dstPort, 8888)

    def test_seq_num(self):
        self.failUnlessEqual(self.p["tcp"].seq_num, 1438057491)
        self.p["tcp"].seq_num = 1111111111
        self.failUnlessEqual(self.p["tcp"].seq_num, 1111111111)

    def test_ack_num(self):
        self.failUnlessEqual(self.p["tcp"].ack_num, 0)
        self.p["tcp"].ack_num = 1111111111
        self.failUnlessEqual(self.p["tcp"].ack_num, 1111111111)

    def test_dataOffset(self):
        self.failUnlessEqual(self.p["tcp"].dataOffset, 11)
        self.p["tcp"].dataOffset = 12
        self.failUnlessEqual(self.p["tcp"].dataOffset, 12)

    def test_reserved(self):
        self.failUnlessEqual(self.p["tcp"].reserved, 0)
        self.p["tcp"].reserved = 8
        self.failUnlessEqual(self.p["tcp"].reserved, 8)

    def test_flags(self):
        self.failUnlessEqual(self.p["tcp"].flags, 2)
        self.p["tcp"].flags = 32
        self.failUnlessEqual(self.p["tcp"].flags, 32)

    def test_flagsoptions(self):
        self.failUnlessEqual(self.p["tcp"].flags, TCP.flags["syn"])
        self.p["tcp"].flags = "rst"
        self.failUnlessEqual(self.p["tcp"].flags, TCP.flags["rst"])

    def test_window(self):
        self.failUnlessEqual(self.p["tcp"].window, 16384)
        self.p["tcp"].window = 2323
        self.failUnlessEqual(self.p["tcp"].window, 2323)

    def test_checksum(self):
        self.failUnlessEqual(self.p["tcp"].checksum, 0xca92)
        cksum = self.p["tcp"].checksum
        self.p["tcp"].checksum = 2323
        self.failUnlessEqual(self.p["tcp"].checksum, 2323)
        self.p["tcp"]._fixChecksums()
        self.failUnlessEqual(cksum, self.p["tcp"].checksum)

    def test_urgent(self):
        self.failUnlessEqual(self.p["tcp"].urgent, 0)
        self.p["tcp"].urgent = 2323
        self.failUnlessEqual(self.p["tcp"].urgent, 2323)

    def test_payloadZero(self):
        self.failIf(len(self.p["tcp"].payload))

    def test_payload(self):
        self.failUnlessEqual(self.p["tcp"].payload, "")
        self.p["tcp"].payload = "asdf"
        self.p.finalise()
        self.failUnlessEqual(self.p["tcp"].payload, "asdf")

    def test_emptyPayload(self):
        self.p["tcp"].payload = ""
        self.p.finalise()
        self.failUnlessEqual(self.p["tcp"].payload, "")

    def test_repr(self):
        repr(self.p)


class uUDP(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("udp")

    def test_srcPort(self):
        self.failUnlessEqual(self.p["udp"].srcPort, 6739)
        self.p["udp"].srcPort = 8888
        self.failUnlessEqual(self.p["udp"].srcPort, 8888)

    def test_dstPort(self):
        self.failUnlessEqual(self.p["udp"].dstPort, 53)
        self.p["udp"].dstPort = 8888
        self.failUnlessEqual(self.p["udp"].dstPort, 8888)

    def test_length(self):
        self.failUnlessEqual(self.p["udp"].length, 31)
        self.p["udp"].length = 8888
        self.failUnlessEqual(self.p["udp"].length, 8888)

    def test_checksum(self):
        self.failUnlessEqual(self.p["udp"].checksum, 30925)
        cksum = self.p["udp"].checksum
        self.p["udp"].checksum = 8888
        self.failUnlessEqual(self.p["udp"].checksum, 8888)
        self.p["udp"]._fixChecksums()
        self.failUnlessEqual(cksum, self.p["udp"].checksum)

    def test_payload(self):
        self.failUnlessEqual(len(self.p["udp"].payload), 23)
        self.p["udp"].payload = "asdf"
        self.failUnlessEqual(self.p["udp"].payload, "asdf")

    def test_payload(self):
        self.failUnless(self.p["udp"].payload)
        self.p["udp"].payload = "asdf"
        self.p.finalise()
        self.failUnlessEqual(self.p["udp"].payload, "asdf")

    def test_repr(self):
        repr(self.p)


class uIP(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp_echo_request")

    def test_version(self):
        self.failUnlessEqual(self.p["ip"].version, 4)
        self.p["ip"].version = 6
        self.failUnlessEqual(self.p["ip"].version, 6)

    def test_headerlength(self):
        self.failUnlessEqual(self.p["ip"].headerLength, 5)
        self.p["ip"].headerLength = 15
        self.failUnlessEqual(self.p["ip"].headerLength, 15)

    def test_tos(self):
        self.failUnlessEqual(self.p["ip"].tos, 0)
        self.p["ip"].tos = 4
        self.failUnlessEqual(self.p["ip"].tos, 4)

    def test_length(self):
        self.failUnlessEqual(self.p["ip"].length, 84)
        self.p["ip"].length = 100
        self.failUnlessEqual(self.p["ip"].length, 100)

    def test_ID(self):
        self.failUnlessEqual(self.p["ip"].ident, 0x3fa8)
        self.p["ip"].ident = 999
        self.failUnlessEqual(self.p["ip"].ident, 999)

    def test_flags(self):
        self.failUnlessEqual(self.p["ip"].flags, 0)
        self.p["ip"].flags = 1 
        self.failUnlessEqual(self.p["ip"].flags, 1)

    def test_flagsoptions(self):
        self.p["ip"].flags = "df"
        self.failUnlessEqual(self.p["ip"].flags, IP.flags["DF"])

    def test_offset(self):
        self.failUnlessEqual(self.p["ip"].fragmentOffset, 0)
        self.p["ip"].fragmentOffset = 8000
        self.failUnlessEqual(self.p["ip"].fragmentOffset, 8000)

    def test_ttl(self):
        self.failUnlessEqual(self.p["ip"].ttl, 64)
        self.p["ip"].ttl = 200
        self.failUnlessEqual(self.p["ip"].ttl, 200)

    def test_protocol(self):
        self.failUnlessEqual(self.p["ip"].protocol, 1)
        self.p["ip"].protocol = 198
        self.failUnlessEqual(self.p["ip"].protocol, 198)

    def test_protocoloptions(self):
        self.failUnlessEqual(self.p["ip"].protocol, ProtocolOptions["icmp"])
        self.p["ip"].protocol = "ah"
        self.failUnlessEqual(self.p["ip"].protocol, ProtocolOptions["ah"])

    def test_checksum(self):
        self.failUnlessEqual(self.p["ip"].checksum, 0x24ff)
        cksum = self.p["ip"].checksum
        self.p["ip"].checksum = 21334
        self.failUnlessEqual(self.p["ip"].checksum, 21334)
        self.p["ip"]._fixChecksums()
        self.failUnlessEqual(self.p["ip"].checksum, cksum)

    def test_src(self):
        self.failUnlessEqual(self.p["ip"].src, "10.0.1.1")
        self.p["ip"].src = "202.7.64.7"
        self.failUnlessEqual(self.p["ip"].src, "202.7.64.7")

    def test_dst(self):
        self.failUnlessEqual(self.p["ip"].dst, "10.0.1.2")
        self.p["ip"].dst = "202.7.64.7"
        self.failUnlessEqual(self.p["ip"].dst, "202.7.64.7")

    def test_payload(self):
        self.failUnlessEqual(len(str(self.p["ip"].payload)), 64)
        self.p["ip"].payload = "asdf"
        self.failUnlessEqual(self.p["ip"].payload, "asdf")

    def test_payload(self):
        self.failUnless(self.p["ip"].payload)
        # Make sure the ICMP checksum doesn't stuff our payload.
        self.p["ip"].protocol = 61
        self.p["ip"].payload = "asdf"
        self.p.finalise()
        self.failUnlessEqual(self.p["ip"].payload, "asdf")

    def test_options(self):
        self.failIf(self.p["ip"].optionsField)

    def test_repr(self):
        repr(self.p)


class uIPOptionsRecordRoute(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("ip_recordroute", pclass=Loopback)

    def test_options(self):
        self.failUnless(self.p["ip"].options["ipoptionrecordroute"])

    def test_length(self):
        self.failUnlessEqual(self.p["ip"].options["ipoptionrecordroute"].length, 39)
        self.p["ip"].options["ipoptionrecordroute"].length = 10
        self.failUnlessEqual(self.p["ip"].options["ipoptionrecordroute"].length, 10)

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
        self.failUnlessEqual(self.p["ip"].options.addrlist, expected)

    def test_nop(self):
        self.failUnlessEqual(len(self.p["ip"].options), 2)
        self.failUnlessEqual(self.p["ip"].options._next.TYPE, "IPOptionEndOfList")


##
# ICMP Test Cases
##
class uICMP(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp_echo_request")

    def test_type(self):
        self.failUnlessEqual(self.p["icmp"].itype, 8)

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp"].checksum, 0x4a5a)
        cksum = self.p["icmp"].checksum
        self.p["icmp"].checksum = 50
        self.failUnlessEqual(self.p["icmp"].checksum, 50)
        self.p["icmp"]._fixChecksums()
        self.failUnlessEqual(self.p["icmp"].checksum, cksum)

    def test_payload(self):
        self.failUnless(self.p["icmp"].payload)
        self.p["icmp"].payload = "asdf"
        self.p.finalise()
        self.failUnlessEqual(self.p["icmp"].payload, "asdf")

    def test_typeoptions(self):
        self.failUnlessEqual(self.p["icmp"].itype, ICMPEchoRequest.itype["icmpechorequest"])
        self.p["icmp"].itype = "icmpechoreply"
        self.failUnlessEqual(self.p["icmp"].itype, ICMPEchoRequest.itype["icmpechoreply"])

    def test_repr(self):
        repr(self.p)


class uICMP_DestinationUnreachable(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp_unreachable")

    def test_iphdr(self):
        self.failUnlessEqual(4, self.p["icmp"].iphdr.version)
        self.failUnlessEqual("192.168.2.2", self.p["icmp"].iphdr.src)

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp"].checksum, 0x17a5)
        cksum = self.p["icmp"].checksum
        self.p["icmp"].checksum = 50
        self.failUnlessEqual(self.p["icmp"].checksum, 50)
        self.p["icmp"]._fixChecksums()
        self.failUnlessEqual(self.p["icmp"].checksum, cksum)

    def test_code(self):
        self.failUnlessEqual(self.p["icmp"].code, ICMPDestinationUnreachable.code["HOST_UNREACHABLE"])

    def test_typeoptions(self):
        self.failUnlessEqual(self.p["icmp"].itype, ICMPDestinationUnreachable.itype["icmpdestinationunreachable"])
        self.p["icmp"].itype = "icmpechoreply"
        self.failUnlessEqual(self.p["icmp"].itype, ICMPDestinationUnreachable.itype["icmpechoreply"])

    def test_repr(self):
        repr(self.p)
        

class uICMP_EchoReply(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp_echo_reply")

    def test_identifier(self):
        self.failUnlessEqual(self.p["icmp"].identifier, 0x0511)

    def test_seqNum(self):
        self.failUnlessEqual(self.p["icmp"].seq_num, 0)

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp"].checksum, 0x745b)
        cksum = self.p["icmp"].checksum
        self.p["icmp"].checksum = 50
        self.failUnlessEqual(self.p["icmp"].checksum, 50)
        self.p["icmp"]._fixChecksums()
        self.failUnlessEqual(self.p["icmp"].checksum, cksum)

    def test_code(self):
        self.failUnlessEqual(self.p["icmp"].code, ICMPEchoReply.code["ECHO_REPLY"])

    def test_payload(self):
        self.failUnlessEqual(len(self.p["icmp"].payload), 56)
        self.failUnlessEqual(self.p["icmp"].payload[-8:], "01234567")
        self.p["icmp"].payload = "ffff"
        self.p.finalise()
        self.failUnlessEqual(self.p["icmp"].payload, "ffff")

    def test_typeoptions(self):
        self.failUnlessEqual(self.p["icmp"].itype, ICMPEchoReply.itype["icmpechoreply"])
        self.p["icmp"].itype = "icmpechorequest"
        self.failUnlessEqual(self.p["icmp"].itype, ICMPEchoReply.itype["icmpechorequest"])

    def test_repr(self):
        repr(self.p)



class uICMP_EchoRequest(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp_echo_request")

    def test_identifier(self):
        self.failUnlessEqual(self.p["icmp"].identifier, 0x050f)

    def test_seqNum(self):
        self.failUnlessEqual(self.p["icmp"].seq_num, 0x18)

    def test_payload(self):
        self.failUnlessEqual(len(self.p["icmp"].payload), 56)
        self.failUnlessEqual(self.p["icmp"].payload[-8:], "01234567")
        self.p["icmp"].payload = "asdf"
        self.p.finalise()
        self.failUnlessEqual(self.p["icmp"].payload, "asdf")

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp"].checksum, 0x4a5a)
        cksum = self.p["icmp"].checksum
        self.p["icmp"].checksum = 50
        self.failUnlessEqual(self.p["icmp"].checksum, 50)
        self.p["icmp"]._fixChecksums()
        self.failUnlessEqual(self.p["icmp"].checksum, cksum)

    def test_code(self):
        self.failUnlessEqual(self.p["icmp"].code, ICMPEchoRequest.code["ECHO_REQUEST"])

    def test_typeoptions(self):
        self.failUnlessEqual(self.p["icmp"].itype, ICMPEchoRequest.itype["icmpechorequest"])
        self.p["icmp"].itype = "icmpechoreply"
        self.failUnlessEqual(self.p["icmp"].itype, ICMPEchoRequest.itype["icmpechoreply"])

    def test_repr(self):
        repr(self.p)


class uICMP_RouterAdvertisement(pcaptester.pcapTester):
    pass

class uICMP_RouterSolicitation(pcaptester.pcapTester):
    pass

class uICMP_TimeExceeded(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp_time_exceeded")

    def test_iphdr(self):
        self.failUnlessEqual(self.p["icmp"].iphdr.version, 4)
        self.failUnlessEqual(self.p["icmp"].iphdr.src, "192.168.0.2")

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp"].checksum, 0xd9ad)
        cksum = self.p["icmp"].checksum
        self.p["icmp"].checksum = 50
        self.failUnlessEqual(self.p["icmp"].checksum, 50)
        self.p["icmp"]._fixChecksums()
        self.failUnlessEqual(self.p["icmp"].checksum, cksum)

    def test_code(self):
        self.failUnlessEqual(self.p["icmp"].code, ICMPTimeExceeded.code["TRANSIT"])

    def test_typeoptions(self):
        self.failUnlessEqual(self.p["icmp"].itype, ICMPTimeExceeded.itype["icmptimeexceeded"])
        self.p["icmp"].itype = "icmpechoreply"
        self.failUnlessEqual(self.p["icmp"].itype, ICMPTimeExceeded.itype["icmpechoreply"])

    def test_repr(self):
        repr(self.p)


class uICMP_TimestampRequest(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp_timestamp_request")

    def test_values(self):
        self.failUnlessEqual(self.p["icmp"].origin_ts, 43666471)
        self.failUnlessEqual(self.p["icmp"].receive_ts, 0)
        self.failUnlessEqual(self.p["icmp"].transmit_ts, 0)

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp"].checksum, 0xf11e)
        cksum = self.p["icmp"].checksum
        self.p["icmp"].checksum = 50
        self.failUnlessEqual(self.p["icmp"].checksum, 50)
        self.p["icmp"]._fixChecksums()
        self.failUnlessEqual(self.p["icmp"].checksum, cksum)

    def test_code(self):
        self.failUnlessEqual(
            self.p["icmp"].code, ICMPTimestampRequest.code["TIMESTAMP_REQUEST"]
        )

    def test_typeoptions(self):
        self.failUnlessEqual(self.p["icmp"].itype, ICMPTimestampRequest.itype["icmptimestamprequest"])
        self.p["icmp"].itype = "icmpechoreply"
        self.failUnlessEqual(self.p["icmp"].itype, ICMPTimestampRequest.itype["icmpechoreply"])

    def test_repr(self):
        repr(self.p)


class uICMP_TimestampReply(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp_timestamp_reply")

    def test_stamps(self):
        self.failUnlessEqual(self.p["icmp"].origin_ts, 43702898)
        self.failUnlessEqual(self.p["icmp"].receive_ts, 2685311235)
        self.failUnlessEqual(self.p["icmp"].transmit_ts, 2685311235)

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp"].checksum, 0xee7c)
        cksum = self.p["icmp"].checksum
        self.p["icmp"].checksum = 50
        self.failUnlessEqual(self.p["icmp"].checksum, 50)
        self.p["icmp"]._fixChecksums()
        self.failUnlessEqual(self.p["icmp"].checksum, cksum)

    def test_code(self):
        self.failUnlessEqual(self.p["icmp"].code, ICMPTimestampReply.code["TIMESTAMP_REPLY"])

    def test_typeoptions(self):
        self.failUnlessEqual(self.p["icmp"].itype, ICMPTimestampReply.itype["icmptimestampreply"])

    def test_repr(self):
        repr(self.p)


class uICMP_AddressMaskRequest(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp_address_mask_request")

    def test_identifier(self):
        self.failUnlessEqual(self.p["icmp"].identifier, 0x134a)

    def test_seqNum(self):
        self.failUnlessEqual(self.p["icmp"].seq_num, 0)

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp"].checksum, 0xdbb5)
        cksum = self.p["icmp"].checksum
        self.p["icmp"].checksum = 50
        self.failUnlessEqual(self.p["icmp"].checksum, 50)
        self.p["icmp"]._fixChecksums()
        self.failUnlessEqual(self.p["icmp"].checksum, cksum)

    def test_code(self):
        self.failUnlessEqual(self.p["icmp"].code, ICMPAddressMaskRequest.code["ADDRESSMASK_REQUEST"])

    def test_typeoptions(self):
        self.failUnlessEqual(self.p["icmp"].itype, ICMPAddressMaskRequest.itype["icmpaddressmaskrequest"])

    def test_repr(self):
        repr(self.p)


class uICMP_AddressMaskReply(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp_address_mask_reply")

    def test_identifier(self):
        self.failUnlessEqual(self.p["icmp"].identifier, 0x134a)

    def test_seqNum(self):
        self.failUnlessEqual(self.p["icmp"].seq_num, 0)

    def test_subnetMask(self):
        self.failUnlessEqual(self.p["icmp"].subnet_mask, "255.255.0.0")

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp"].checksum, 0xdab5)
        cksum = self.p["icmp"].checksum
        self.p["icmp"].checksum = 50
        self.failUnlessEqual(self.p["icmp"].checksum, 50)
        self.p["icmp"]._fixChecksums()
        self.failUnlessEqual(self.p["icmp"].checksum, cksum)

    def test_code(self):
        self.failUnlessEqual(self.p["icmp"].code, ICMPAddressMaskReply.code["ADDRESSMASK_REPLY"])

    def test_repr(self):
        repr(self.p)

    def test_typeoptions(self):
        self.failUnlessEqual(self.p["icmp"].itype, ICMPAddressMaskReply.itype["icmpaddressmaskreply"])


if sys.byteorder == "little":
    # The Enc interface headers are in host byte-order. The sample dump is
    # taken on an i386 system, so we disable these tests on big-endian systems. 
    class uEnc(pcaptester.pcapTester):
        def setUp(self):
            self.p = self.getpacket("enc")

        def test_addressFamily(self):
            self.failUnlessEqual(self.p["enc"].addressFamily, 2)
            self.p["enc"].addressFamily = 5
            self.failUnlessEqual(self.p["enc"].addressFamily, 5)

        def test_spi(self):
            self.failUnlessEqual(self.p["enc"].spi, 0x10f2)
            self.p["enc"].spi = 0xffff
            self.failUnlessEqual(self.p["enc"].spi, 0xffff)

        def test_flags(self):
            self.failUnlessEqual(self.p["enc"].flags, 10240)
            self.p["enc"].flags = 32
            self.failUnlessEqual(self.p["enc"].flags, 32)

        def test_flagsoptions(self):
            self.failUnless(self.p["enc"].flags & Enc.flags["auth"])
            self.p["enc"].flags = "auth_ah"
            self.failUnlessEqual(self.p["enc"].flags, Enc.flags["auth_ah"])

        def test_nextproto(self):
            self.failUnless(self.p.has_key("icmp"))

        def test_repr(self):
            repr(self.p)

class uPfOld(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("pf.old")

    def test_safamily(self):
        p = self.p["pfold"]
        self.failUnlessEqual(self.p["pfold"].safamily, self.p["pfold"].SAFamilyOptions["INET"])
        self.p["pfold"].safamily = 5
        self.failUnlessEqual(self.p["pfold"].safamily, 5)

    def test_ifname(self):
        p = self.p["pfold"]
        self.failUnlessEqual(self.p["pfold"].ifname, "tun0")
        self.p["pfold"].ifname = "bomb"
        self.failUnlessEqual(self.p["pfold"].ifname, "bomb")

    def test_ruleno(self):
        p = self.p["pfold"]
        self.failUnlessEqual(self.p["pfold"].ruleno, 0)
        self.p["pfold"].ruleno = 5
        self.failUnlessEqual(self.p["pfold"].ruleno, 5)

    def test_reason(self):
        self.failUnlessEqual(self.p["pfold"].reason, PFOld.ReasonOptions["MATCH"])
        self.p["pfold"].reason = 4
        self.failUnlessEqual(self.p["pfold"].reason, 4)

    def test_action(self):
        self.failUnlessEqual(self.p["pfold"].action, PFOld.ActionOptions["DROP"])
        self.p["pfold"].action = 5
        self.failUnlessEqual(self.p["pfold"].action, 5)

    def test_direction(self):
        self.failUnlessEqual(self.p["pfold"].direction, PFOld.DirectionOptions["IN"])
        self.p["pfold"].direction = 5
        self.failUnlessEqual(self.p["pfold"].direction, 5)

    def test_encap(self):
        self.failUnlessEqual(self.p["pfold"]._next.src, "68.18.67.181")

    def test_payload(self):
        self.failUnless(self.p["pfold"].payload)
        self.p["pfold"].safamily = self.p["pfold"].SAFamilyOptions["UNSPEC"]
        self.p["pfold"].payload = "asdf"
        self.p.finalise()
        self.failUnlessEqual(self.p["pfold"].payload, "asdf")

    def test_repr(self):
        repr(self.p)


class uPf(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("pf")

    def test_length(self):
        self.failUnlessEqual(self.p["pf"].length, 45)
        self.p["pf"].length = 5
        self.failUnlessEqual(self.p["pf"].length, 5)

    def test_safamily(self):
        self.failUnlessEqual(self.p["pf"].safamily, self.p["pf"].SAFamilyOptions["INET"])
        self.p["pf"].safamily = 5
        self.failUnlessEqual(self.p["pf"].safamily, 5)

    def test_action(self):
        self.failUnlessEqual(self.p["pf"].action, PF.ActionOptions["DROP"])
        self.p["pf"].action = 5
        self.failUnlessEqual(self.p["pf"].action, 5)

    def test_reason(self):
        self.failUnlessEqual(self.p["pf"].reason, PF.ReasonOptions["MATCH"])
        self.p["pf"].reason = 5
        self.failUnlessEqual(self.p["pf"].reason, 5)

    def test_ifname(self):
        self.failUnlessEqual(self.p["pf"].ifname, "lo0")
        self.p["pf"].ifname = "foo"
        self.failUnlessEqual(self.p["pf"].ifname, "foo")

    def test_ruleset(self):
        self.failUnlessEqual(self.p["pf"].ruleset, "")
        self.p["pf"].ruleset = "foo"
        self.failUnlessEqual(self.p["pf"].ruleset, "foo")

    def test_rulenr(self):
        self.failUnlessEqual(self.p["pf"].rulenr, 1)
        self.p["pf"].rulenr = 5
        self.failUnlessEqual(self.p["pf"].rulenr, 5)

    def test_subrulenr(self):
        self.failUnlessEqual(self.p["pf"].subrulenr, (1L << 32)-1)
        self.p["pf"].subrulenr = 5
        self.failUnlessEqual(self.p["pf"].subrulenr, 5)

    def test_direction(self):
        self.failUnlessEqual(self.p["pf"].direction, PF.DirectionOptions["OUT"])
        self.p["pf"].direction = 3
        self.failUnlessEqual(self.p["pf"].direction, 3)

    def test_pad(self):
        self.failUnlessEqual(self.p["pf"].pad, "\0\0\0")
        self.p["pf"].pad = "xxx"
        self.failUnlessEqual(self.p["pf"].pad, "xxx")
    
    def test_next(self):
        self.failUnlessEqual(self.p["pf"]._next.src, "127.0.0.1")

    def test_payload(self):
        self.failUnlessEqual(self.p["pf"].payload[:5], "E\x00\x00T\xf1")
        self.p["pf"].safamily = self.p["pf"].SAFamilyOptions["UNSPEC"]
        self.p["pf"].payload = "asdf"
        self.p.finalise()
        self.failUnlessEqual(self.p["pf"].payload, "asdf")

    def test_repr(self):
        repr(self.p)


class uLoopBack(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("ip_recordroute")

    def test_addressFamily(self):
        self.failUnless(self.p["Loopback"].addressFamily == 2)
        self.p["Loopback"].addressFamily = 3
        self.failUnless(self.p["Loopback"].addressFamily == 3)

    def test_addressFamilyOptions(self):
        self.failUnless(self.p["Loopback"].addressFamily == self.p["Loopback"].AFOptions["inet"])
        self.p["Loopback"].addressFamily = "link"
        self.failUnless(self.p["Loopback"].addressFamily == self.p["Loopback"].AFOptions["link"])

    def test_getProtoList(self):
        protos = self.p.protostack._getProtoList()
        self.failUnlessEqual(protos, protos[0]._getProtoList())
        self.failUnlessEqual(protos, protos[1]._getProtoList())
        self.failUnlessEqual(protos, protos[2]._getProtoList())

    def test_getProtoListInclusive(self):
        names = [i.TYPE for i in self.p.getProtoList()]
        self.failUnlessEqual(names, ["Loopback", "IP", "ICMPEchoRequest"])

    def test_payload(self):
        self.failUnless(self.p["loopback"].payload)
        self.p["loopback"].payload = "asdf"
        self.failUnlessEqual(self.p["loopback"].payload, "asdf")

    def test_repr(self):
        repr(self.p)



class uIPv6(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp6_neighbor_sol")

    def test_version(self):
        self.failUnlessEqual(self.p["ipv6"].version, 6)
        self.p["ipv6"].version = 10
        self.failUnlessEqual(self.p["ipv6"].version, 10)

    def test_diffservices(self):
        self.failUnlessEqual(self.p["ipv6"].diffservices, 0)
        self.p["ipv6"].diffservices = 10
        self.failUnlessEqual(self.p["ipv6"].diffservices, 10)

    def test_flowlabel(self):
        self.failUnlessEqual(self.p["ipv6"].flowlabel, 0)
        self.p["ipv6"].flowlabel = 10
        self.failUnlessEqual(self.p["ipv6"].flowlabel, 10)

    def test_payloadlength(self):
        self.failUnlessEqual(self.p["ipv6"].payloadlength, 32)
        self.p["ipv6"].payloadlength = 30
        self.failUnlessEqual(self.p["ipv6"].payloadlength, 30)

    def test_nextheader(self):
        self.failUnlessEqual(self.p["ipv6"].nextheader, 0x3a)
        self.p["ipv6"].nextheader = 30
        self.failUnlessEqual(self.p["ipv6"].nextheader, 30)

    def test_nextheaderOptions(self):
        self.failUnlessEqual(self.p["ipv6"].nextheader, ProtocolOptions["icmp6"])
        self.p["ipv6"].nextheader = "esp"
        self.failUnlessEqual(self.p["ipv6"].nextheader, ProtocolOptions["esp"])

    def test_hoplimit(self):
        self.failUnlessEqual(self.p["ipv6"].hoplimit, 255)
        self.p["ipv6"].hoplimit = 30
        self.failUnlessEqual(self.p["ipv6"].hoplimit, 30)

    def test_src(self):
        self.failUnlessEqual(self.p["ipv6"].src, "fe80::205:3cff:fe04:c8cf")
        self.p["ipv6"].src = "fe80:0:0:0:ffff:ffff:aaaa:2222"
        self.failUnlessEqual(self.p["ipv6"].src, "fe80::ffff:ffff:aaaa:2222")

    def test_dst(self):
        self.failUnlessEqual(self.p["ipv6"].dst, "ff02::1:ff68:5b6e")
        self.p["ipv6"].dst = "fe80:0:0:0:ffff:ffff:aaaa:2222"
        self.failUnlessEqual(self.p["ipv6"].dst, "fe80::ffff:ffff:aaaa:2222")

    def test_payload(self):
        self.failUnlessEqual(len(str(self.p["ipv6"].payload)), self.p["ipv6"].payloadlength)
        self.p["ipv6"].payload = "adsffff"
        self.p.finalise()
        self.failUnless(self.p["ipv6"].payload, "asdffff")

    def test_repr(self):
        repr(self.p)

##
# ICMP6 Test Cases
##
class uICMP6(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp6_neighbor_sol")

    def test_icmp6type(self):
        self.failUnlessEqual(self.p["icmp6"].icmp6type, 135)
        self.p["icmp6"].icmp6type = 20
        self.failUnlessEqual(self.p["icmp6"].icmp6type, 20)

    def test_icmp6typeOptions(self):
        self.failUnlessEqual(
            self.p["icmp6"].icmp6type,
            ICMP6NeighbourSolicitation.icmp6type["neighbour_solicitation"]
        )
        self.p["icmp6"].icmp6type = "echo_reply"
        self.failUnlessEqual(
            self.p["icmp6"].icmp6type,
            ICMP6NeighbourSolicitation.icmp6type["echo_reply"]
        )

    def test_code(self):
        self.failUnlessEqual(self.p["icmp6"].code, 0)
        self.p["icmp6"].code = 20
        self.failUnlessEqual(self.p["icmp6"].code, 20)

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp6"].checksum, 0x5e35)
        self.p["icmp6"].checksum = 20
        self.failUnlessEqual(self.p["icmp6"].checksum, 20)
        self.p["icmp6"]._fixChecksums()
        self.failUnlessEqual(self.p["icmp6"].checksum, 0x5e35)

    def test_repr(self):
        repr(self.p)



class uICMP6_EchoRequest(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp6_echorequest")

    def test_icmp6type(self):
        self.failUnlessEqual(self.p["icmp6"].icmp6type, 128)
        self.p["icmp6"].icmp6type = 20
        self.failUnlessEqual(self.p["icmp6"].icmp6type, 20)

    def test_icmp6typeOptions(self):
        self.failUnlessEqual(
            self.p["icmp6"].icmp6type,
            ICMP6EchoRequest.icmp6type["echo_request"]
        )
        self.p["icmp6"].icmp6type = "echo_reply"
        self.failUnlessEqual(
            self.p["icmp6"].icmp6type,
            ICMP6EchoRequest.icmp6type["echo_reply"]
        )

    def test_code(self):
        self.failUnlessEqual(self.p["icmp6"].code, 0)
        self.p["icmp6"].code = 20
        self.failUnlessEqual(self.p["icmp6"].code, 20)

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp6"].checksum, 0xabeb)
        self.p["icmp6"].checksum = 20
        self.failUnlessEqual(self.p["icmp6"].checksum, 20)

    def test_identifier(self):
        self.failUnlessEqual(self.p["icmp6"].identifier, 0x6a1e)
        self.p["icmp6"].identifier = 20
        self.failUnlessEqual(self.p["icmp6"].identifier, 20)

    def test_seqnum(self):
        self.failUnlessEqual(self.p["icmp6"].seq_num, 0x0000)
        self.p["icmp6"].seq_num = 20
        self.failUnlessEqual(self.p["icmp6"].seq_num, 20)

    def test_repr(self):
        repr(self.p)


class uICMP6_EchoReply(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp6_echoreply")

    def test_icmp6type(self):
        self.failUnlessEqual(self.p["icmp6"].icmp6type, 129)
        self.p["icmp6"].icmp6type = 20
        self.failUnlessEqual(self.p["icmp6"].icmp6type, 20)

    def test_icmp6typeOptions(self):
        self.failUnlessEqual(
            self.p["icmp6"].icmp6type,
            ICMP6EchoReply.icmp6type["echo_reply"]
        )
        self.p["icmp6"].icmp6type = "echo_request"
        self.failUnlessEqual(
            self.p["icmp6"].icmp6type,
            ICMP6EchoReply.icmp6type["echo_request"]
        )

    def test_code(self):
        self.failUnlessEqual(self.p["icmp6"].code, 0)
        self.p["icmp6"].code = 20
        self.failUnlessEqual(self.p["icmp6"].code, 20)

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp6"].checksum, 0x0d89)
        self.p["icmp6"].checksum = 20
        self.failUnlessEqual(self.p["icmp6"].checksum, 20)

    def test_identifier(self):
        self.failUnlessEqual(self.p["icmp6"].identifier, 0x2e2e)
        self.p["icmp6"].identifier = 20
        self.failUnlessEqual(self.p["icmp6"].identifier, 20)

    def test_seqnum(self):
        self.failUnlessEqual(self.p["icmp6"].seq_num, 0x0000)
        self.p["icmp6"].seq_num = 20
        self.failUnlessEqual(self.p["icmp6"].seq_num, 20)

    def test_repr(self):
        repr(self.p)


class uICMP6_NeighborSolicitation(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp6_neighbor_sol")

    def test_icmp6type(self):
        self.failUnlessEqual(self.p["icmp6"].icmp6type, 135)
        self.p["icmp6"].icmp6type = 20
        self.failUnlessEqual(self.p["icmp6"].icmp6type, 20)

    def test_icmp6typeOptions(self):
        self.failUnlessEqual(
            self.p["icmp6"].icmp6type,
            ICMP6NeighbourSolicitation.icmp6type["neighbour_solicitation"]
        )
        self.p["icmp6"].icmp6type = "echo_request"
        self.failUnlessEqual(
            self.p["icmp6"].icmp6type,
            ICMP6NeighbourSolicitation.icmp6type["echo_request"]
        )

    def test_code(self):
        self.failUnlessEqual(self.p["icmp6"].code, 0)
        self.p["icmp6"].code = 20
        self.failUnlessEqual(self.p["icmp6"].code, 20)

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp6"].checksum, 0x5e35)
        self.p["icmp6"].checksum = 20
        self.failUnlessEqual(self.p["icmp6"].checksum, 20)

    def test_targetAddress(self):
        self.failUnlessEqual(self.p["icmp6"].target_addr, "fe80::209:5bff:fe68:5b6e")
        self.p["icmp6"].target_addr = "fe80:0:0:0:ffff:ffff:aaaa:2222"
        self.failUnlessEqual(self.p["icmp6"].target_addr, "fe80::ffff:ffff:aaaa:2222")

    def test_optionsAddress(self):
        self.failUnlessEqual(self.p["icmp6"].options, "00:05:3c:04:c8:cf")
        self.p["icmp6"].options = "00:05:3c:04:fa:fa"
        self.failUnlessEqual(self.p["icmp6"].options, "00:05:3c:04:fa:fa")

    def test_repr(self):
        repr(self.p)


class uICMP6_NeighborAdvertisement(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp6_neighbor_advertisement")

    def test_icmp6type(self):
        self.failUnlessEqual(self.p["icmp6"].icmp6type, 136)
        self.p["icmp6"].icmp6type = 20
        self.failUnlessEqual(self.p["icmp6"].icmp6type, 20)

    def test_icmp6typeOptions(self):
        self.failUnlessEqual(
            self.p["icmp6"].icmp6type,
            ICMP6NeighbourSolicitation.icmp6type["neighbour_advertisement"]
        )
        self.p["icmp6"].icmp6type = "echo_request"
        self.failUnlessEqual(
            self.p["icmp6"].icmp6type,
            ICMP6NeighbourAdvertisement.icmp6type["echo_request"]
        )

    def test_code(self):
        self.failUnlessEqual(self.p["icmp6"].code, 0)
        self.p["icmp6"].code = 20
        self.failUnlessEqual(self.p["icmp6"].code, 20)

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp6"].checksum, 0x5cf8)
        self.p["icmp6"].checksum = 20
        self.failUnlessEqual(self.p["icmp6"].checksum, 20)

    def test_targetAddress(self):
        self.failUnlessEqual(self.p["icmp6"].target_addr, "fe80::2e0:29ff:fe94:495d")
        self.p["icmp6"].target_addr = "fe80:0:0:0:ffff:ffff:aaaa:2222"
        self.failUnlessEqual(self.p["icmp6"].target_addr, "fe80::ffff:ffff:aaaa:2222")

    def test_optionsAddress(self):
        self.failUnlessEqual(self.p["icmp6"].options, "00:e0:29:94:49:5d")
        self.p["icmp6"].options = "00:05:3c:04:fa:fa"
        self.failUnlessEqual(self.p["icmp6"].options, "00:05:3c:04:fa:fa")
        
    def test_flags(self):
        self.failUnlessEqual(self.p["icmp6"].flags, 3)
        opts = ICMP6NeighbourAdvertisement.flags
        self.p["icmp6"].flags =     opts["ROUTER"] |\
                                    opts["SOLICITED"] |\
                                    opts["OVERRIDE"]
        self.failUnlessEqual(self.p["icmp6"].flags, 7)

    def test_flagsoptions(self):
        self.failUnlessEqual(self.p["icmp6"].flags,
            ICMP6NeighbourAdvertisement.flags["OVERRIDE"] |\
            ICMP6NeighbourAdvertisement.flags["SOLICITED"]\
        )
        self.p["icmp6"].flags = ("router", "solicited", "override")
        self.failUnlessEqual(self.p["icmp6"].flags, 7)

    def test_repr(self):
        repr(self.p)

class uICMP6_ParameterProblem(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("icmp6_parameter_problem", pclass=Loopback)

    def test_icmp6type(self):
        self.failUnlessEqual(self.p["icmp6"].icmp6type, 4)
        self.p["icmp6"].icmp6type = 20
        self.failUnlessEqual(self.p["icmp6"].icmp6type, 20)

    def test_icmp6typeOptions(self):
        self.failUnlessEqual(
            self.p["icmp6"].icmp6type,
            ICMP6ParameterProblem.icmp6type["parameter_problem"]
        )
        self.p["icmp6"].icmp6type = "echo_request"
        self.failUnlessEqual(
            self.p["icmp6"].icmp6type,
            ICMP6ParameterProblem.icmp6type["echo_request"]
        )

    def test_code(self):
        self.failUnlessEqual(self.p["icmp6"].code, 0)
        self.p["icmp6"].code = 20
        self.failUnlessEqual(self.p["icmp6"].code, 20)

    def test_checksum(self):
        self.failUnlessEqual(self.p["icmp6"].checksum, 0xe93e)
        self.p["icmp6"].checksum = 20
        self.failUnlessEqual(self.p["icmp6"].checksum, 20)

    def test_pointer(self):
        self.failUnlessEqual(self.p["icmp6"].pointer, 0x002c)
        self.p["icmp6"].pointer = 0x003c
        self.failUnlessEqual(self.p["icmp6"].pointer, 0x003c)

    def test_repr(self):
        repr(self.p)

class uARP(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("arprequest")

    def test_hardware_type(self):
        self.failUnlessEqual(self.p["arp"].hardware_type, 1)

    def test_protocol_type(self):
        self.failUnlessEqual(self.p["arp"].protocol_type, 0x800)

    def test_hardware_size(self):
        self.failUnlessEqual(self.p["arp"].hardware_size, 6)

    def test_protocol_size(self):
        self.failUnlessEqual(self.p["arp"].hardware_size, 6)

    def test_opcode(self):
        self.failUnlessEqual(self.p["arp"].opcode, 1)

    def test_opcodeoptions(self):
        self.failUnlessEqual(
            self.p["arp"].opcode,
            ARP.opcode["arp_request"]
        )
        self.p["arp"].opcode = "rarp_request"
        self.failUnlessEqual(
            self.p["arp"].opcode,
            ARP.opcode["rarp_request"]
        )

    def test_sender_hardware_addr(self):
        self.failUnlessEqual(self.p["arp"].sender_hardware_addr, "00:e0:7d:d4:60:ba")
        self.p["arp"].sender_hardware_addr = "00:e0:7d:d4:fa:fa"
        self.failUnlessEqual(self.p["arp"].sender_hardware_addr, "00:e0:7d:d4:fa:fa")

    def test_sender_proto_addr(self):
        self.failUnlessEqual(self.p["arp"].sender_proto_addr, "192.168.0.2")
        self.p["arp"].sender_proto_addr = "192.168.1.1"
        self.failUnlessEqual(self.p["arp"].sender_proto_addr, "192.168.1.1")

    def test_target_hardware_addr(self):
        self.failUnlessEqual(self.p["arp"].target_hardware_addr, "00:00:00:00:00:00")
        self.p["arp"].target_hardware_addr = "00:e0:7d:d4:fa:fa"
        self.failUnlessEqual(self.p["arp"].target_hardware_addr, "00:e0:7d:d4:fa:fa")

    def test_target_proto_addr(self):
        self.failUnlessEqual(self.p["arp"].target_proto_addr, "192.168.0.20")
        self.p["arp"].target_proto_addr = "192.168.1.1"
        self.failUnlessEqual(self.p["arp"].target_proto_addr, "192.168.1.1")

    def test_repr(self):
        repr(self.p)


class uIPESP(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("ip_esp")

    def test_proto(self):
        self.failUnless(self.p.has_key("esp"))

    def test_spi(self):
        self.failUnlessEqual(self.p["esp"].spi, 0x100a)
        self.p["esp"].spi = 0xfff
        self.failUnlessEqual(self.p["esp"].spi, 0xfff)

    def test_sequence(self):
        self.failUnlessEqual(self.p["esp"].sequence, 1)
        self.p["esp"].sequence = 12
        self.failUnlessEqual(self.p["esp"].sequence, 12)

    def test_payload(self):
        self.p["esp"].payload


class uIPAH(pcaptester.pcapTester):
    def setUp(self):
        self.p = self.getpacket("ip_ah")

    def test_nextheader(self):
        self.failUnlessEqual(self.p["ah"].nextheader, 0x01)
        self.p["ah"].nextheader = "IGMP"
        self.failUnlessEqual(self.p["ah"].nextheader, 0x02)

    def test_length(self):
        self.failUnlessEqual(self.p["ah"].length, 4)
        self.p["ah"].length = 18
        self.failUnlessEqual(self.p["ah"].length, 18)

    def test_reserved(self):
        self.failUnlessEqual(self.p["ah"].reserved, 0)
        self.p["ah"].reserved = 18
        self.failUnlessEqual(self.p["ah"].reserved, 18)

    def test_spi(self):
        self.failUnlessEqual(self.p["ah"].spi, 0x10f2)
        self.p["ah"].spi = 18
        self.failUnlessEqual(self.p["ah"].spi, 18)

    def test_sequence(self):
        self.failUnlessEqual(self.p["ah"].sequence, 2759484411)
        self.p["ah"].sequence = 18
        self.failUnlessEqual(self.p["ah"].sequence, 18)

    def test_payload(self):
        self.failUnless(self.p["ah"].payload.startswith("\x08\x00"))

    def test_icv(self):
        self.failUnless(self.p["ah"].icv.startswith("\x48\xc4"))
        self.failUnless(self.p["ah"].icv.endswith("\x27\xcb"))

    def test_nextheader(self):
        self.failUnless(self.p.has_key("icmp"))


