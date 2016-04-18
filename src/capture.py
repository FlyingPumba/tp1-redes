#! /usr/bin/env python
import sys
from scapy.all import *

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print ''
        print "Usage: " + sys.argv[0] + " <interface> <segundos>"
    else:
        interface = sys.argv[1]
        tiempo = int(sys.argv[2])
        p = sniff(iface = interface, timeout = tiempo)
        wrpcap("captura.cap", p)
