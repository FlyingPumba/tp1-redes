#! /usr/bin/env python
import sys
import time
from scapy.all import *

def getLayersList(pkt):
    res = []
    res.append(pkt.name)
    while pkt.payload:
        pkt = pkt.payload
        res.append(pkt.name)
    return res

types = []
def entropiaEthernet(pkt):
    global types
    if Ether in pkt:
        s = pkt.getlayer(1).summary().partition(' ')[0]
        print ">> {0}".format(pkt.summary())
        if exp == "exp-proto":
            with open("exp-proto.dat","a+") as f:
                f.write(pkt.getlayer(1).summary()+"\n")
        types.append(s)

hosts = set()
def hostsArp(pkt):
    if ARP in pkt:
        print ">> {0}".format(pkt.summary())
        if pkt[ARP].op == 1:
            #who-has
            # print pkt.sprintf("%ARP.hwsrc%") 
            # %ARP.psrc% %ARP.pdst%"
            hosts.add(pkt[ARP].hwsrc)
        else:
            #reply
            # print pkt.sprintf("%ARP.hwdst%") 
            # %ARP.psrc% %ARP.pdst%"
            hosts.add(pkt[ARP].hwdst)

time_start = 0
def timeStopper(pkt):
    global time_start, types
    time_stop = time.time()
    diff = time_stop - time_start
    if diff > tiempo: # 10 segundos
        if exp == "entropia-tipos" or exp == "exp-proto":
            # computar entropia de types
            calcularEntropia(types)
        elif exp == "nodos-ARP":
            print hosts
        return True
    else:
        return False

count = 0
def countStopper(pkt):
    global count # Needed to modify global copy of count
    if count > 50:
        return True
    else:
        count = count + 1
        return False

def calcularEntropia(lista):
    elementosDistintos = {}
    # contamos las apariciones de cada elemento distinto
    for elem in lista:
        if elem not in elementosDistintos:
            elementosDistintos[elem] = 1
        else:
            elementosDistintos[elem] = elementosDistintos[elem] + 1
    # calculamos la entropia
    entropia = 0
    print "\nElementos de la fuente de informacion:"
    print elementosDistintos
    for elem, apariciones in elementosDistintos.iteritems():
        proba = float(apariciones)/float(len(lista))
        print "Simbolo {0} tiene probabilidad {1}".format(elem, proba)
        if exp == "exp-proto":
            with open("exp-proto.dat","a+") as f:
                f.write("Simbolo {0} tiene probabilidad {1}\n".format(elem, proba))
        entropia += proba * (- math.log(proba)/math.log(2))

    print "\nLa entropia de la fuente es {0}".format(entropia)
    if exp == "exp-proto":
        with open("exp-proto.dat","a+") as f:
            f.write("La entropia de la fuente es {0} \n".format(entropia))

exp = ""
tiempo = 10
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print ''
        print "Usage: " + sys.argv[0] + " <interface> <exp>"
        print "\tDonde <exp> puede ser: \"entropia-tipos\", \"nodos-ARP\""
    elif len(sys.argv) > 2:
        interface = sys.argv[1]
        time_start = time.time()
        exp = sys.argv[2]
        if len(sys.argv) > 3:
            tiempo = int(sys.argv[3])
        if exp == "entropia-tipos" or exp == "exp-proto":
            sniff(iface = interface, prn = entropiaEthernet, stop_filter = timeStopper)
        elif exp == "nodos-ARP":
            sniff(iface = interface, prn = hostsArp, stop_filter = timeStopper)
