import openbsd.pcap

def callback(packet, tstamp, length):
    print repr(packet), tstamp, length

p = openbsd.pcap.Live("wi0")
p.filter("host basho and tcp port 22")
p.loop(10, callback)
