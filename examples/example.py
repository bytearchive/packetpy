#!/usr/bin/env python

import openbsd

o = openbsd.pcap.Offline("foo")
o.filter("ip")
packet = o.next(interpret=1)[0]
print packet
packet["ip"].src = "192.168.100.1"
packet.finalise()
print packet
