#! /usr/bin/env python
import sys
from scapy.all import *

def packteHandler(pkt):
    print pkt.summary()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print ''
        print "Usage: " + sys.argv[0] + " <interface>"
    elif len(sys.argv) > 1:
        interface = sys.argv[1]
        p = sniff(iface = interface, prn = packteHandler)
