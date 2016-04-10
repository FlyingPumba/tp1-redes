#! /usr/bin/env python
import sys
from scapy.all import *

def getLayersList(pkt):
    res = []
    res.append(pkt.name)
    while pkt.payload:
        pkt = pkt.payload
        res.append(pkt.name)
    return res

types = []
def packteHandler(pkt):
    global types
    print pkt.summary()
    try:
        types.append(pkt.type)
    except AttributeError:
        print "No type"

count = 0
def stopper(pkt):
    global count # Needed to modify global copy of count
    if count > 50:
        return True
    else:
        count = count + 1
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print ''
        print "Usage: " + sys.argv[0] + " <interface>"
    elif len(sys.argv) > 1:
        interface = sys.argv[1]
        p = sniff(iface = interface, prn = packteHandler, stop_filter = stopper)
