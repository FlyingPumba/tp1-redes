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
        if (s == "IP" or s == "IPv6" or s == "ARP"):
            print ">> {0}".format(pkt.summary())
            if exp == "exp-proto":
                with open("exp-proto.dat","a+") as f:
                    f.write(pkt.getlayer(1).summary()+"\n")
            types.append(s)

nodos_dst = []
nodos_src = []
def nodosDistinguidos(pkt):
    print ">> {0}".format(pkt.summary())
    if pkt[ARP].op == 1: #who-has
        nodos_dst.append(pkt[ARP].pdst)
        nodos_src.append(pkt[ARP].psrc)

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
if __name__ == "__main__":
    # ip = [x[4] for x in  scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
    # bdcst = [x[2] for x in  scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]

    tiempo = 60 * 5

    if len(sys.argv) < 2:
        print ''
        print "Usage: " + sys.argv[0] + " <interface> <exp>"
        print "\tDonde <exp> puede ser: \"entropia-tipos\", \"exp-proto\", \"exp-nodos\", \"nodos-ARP\""
    elif len(sys.argv) > 2:
        interface = sys.argv[1]
        time_start = time.time()
        exp = sys.argv[2]
        if len(sys.argv) > 3:
            tiempo = int(sys.argv[3])
        if exp == "entropia-tipos":
            sniff(iface = interface, prn = entropiaEthernet, timeout = tiempo)
            calcularEntropia(types)
        elif exp == "exp-proto":
            p = sniff(iface = interface, prn = entropiaEthernet, timeout = tiempo)
            calcularEntropia(types)
        elif exp == "exp-nodos":
            p = sniff(iface = interface, prn = nodosDistinguidos, timeout = tiempo, filter="arp")
            print "Entropia destino paquetes ARP Who Has"
            calcularEntropia(nodos_dst)
            print "Entropia fuente paquetes ARP Who Has"
            calcularEntropia(nodos_src)
        elif exp == "nodos-ARP":
            sniff(iface = interface, prn = hostsArp, timeout = 60)
            print hosts
