#!/usr/bin/env python2.5
import time
from optparse import OptionParser
import packet.pcap

def callback_dummy(pack, ts, length):
    pass


def callback_print(pack, ts, length):
    print pack


def main():
    parser = OptionParser()
    parser.add_option(
        "--time", "-t", dest= "time", default=False, action="store_true",
        help="Suppress output, but print the time taken for traversal after completion.",
    )
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.error("Must pass at least one argument.")
    feed = packet.pcap.Offline(args[0])
    if options.time:
        start = time.time()
        feed.dispatch(-1, callback_dummy, True)
        end = time.time()
        print "Time: %s"%(end-start)
    else:
        feed.dispatch(-1, callback_print, True)
    feed.close()
            

if __name__ == "__main__":
    main()
