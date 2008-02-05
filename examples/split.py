#!/usr/bin/env python2.5

"""
Splits a dump file into n chunks of COUNT packets
"""

from optparse import OptionParser
import packet.pcap

OUTPUTFILENAME = "%s.%s.dump"

class Handler(object):
    counter = 0
    def __init__(self, feed, output, count):
        self.feed = feed
        self.output = output
        self.count = count
        self.dumper = packet.pcap.Dumper(
            self.feed,
            OUTPUTFILENAME % (
                self.output,
                str(self.counter / self.count)
            )
        )

    def callback(self, pack, ts, length):
        if self.counter == 0:
            self.dumper(pack, ts, length)
        elif self.counter % self.count == 0:
            # Start a new dump
            self.dumper.close()
            self.dumper = packet.pcap.Dumper(
                self.feed,
                OUTPUTFILENAME % (
                    self.output,
                    str(self.counter / self.count)
                )
            )
        self.dumper(pack, ts, length)
        self.counter += 1

    def close(self):
        self.dumper.close()
            

def main():
    parser = OptionParser()
    parser.add_option(
        "--input", "-i", dest="input",
        help="filename to read from",
    )
    parser.add_option(
        "--output", "-o", dest="output",
        help="output filename prefix",
    )
    parser.add_option(
        "--count", dest="count", type="int", default=20000,
        help="write n packets per chunk [resulting in a len(chunk) = len(packets) / count]",
    )
    (options, args) = parser.parse_args()

    feed = packet.pcap.Offline(options.input)
    h = Handler(feed, options.output, options.count)
    feed.dispatch(-1, h.callback)
    h.close()


if __name__ == "__main__":
    main()
