#! /usr/bin/env python
import sys
import time
import operator
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
        types.append(s)

nodos_dst = []
def nodosDistinguidos(pkt):
    if ARP in pkt:
        print ">> {0}".format(pkt.summary())
        if pkt[ARP].op == 1: #who-has
            nodos_dst.append(pkt[ARP].pdst)

def calcularEntropia(lista):
    elementosDistintos = {}
    infoElemento = {}
    # contamos las apariciones de cada elemento distinto
    for elem in lista:
        if elem not in elementosDistintos:
            elementosDistintos[elem] = 1
        else:
            elementosDistintos[elem] = elementosDistintos[elem] + 1
    # calculamos la entropia
    entropia = 0
    sum_0025 = 0.0
    sum_0005 = 0.0
    #print "\nElementos de la fuente de informacion:"
    #print elementosDistintos
    archivo = open("resul_nodos.txt", "w")
    for elem, apariciones in elementosDistintos.iteritems():
        proba = float(apariciones)/float(len(lista))
        info = (- math.log(proba)/math.log(2))
        elementosDistintos[elem] = proba
        infoElemento[elem] = info
        i = "%.3f" % info
        s = str(elem) + " " + i + "\n"
        archivo.write(s)
        if proba <= 0.005:
            sum_0005 += proba
        elif proba <= 0.025:
            sum_0025 += proba
        entropia += proba * info

    sorted_elems = sorted(elementosDistintos.items(), key=operator.itemgetter(1), reverse=True)
    
    for tupla in sorted_elems:
        if tupla[1] > 0.025:
            print "Simbolo {0} tiene probabilidad {1}".format(tupla[0], tupla[1])
    print "Los simbolos con probabilidad menor o igual a 0.025 suman probabilidad {0}".format(sum_0025)
    print "Los simbolos con probabilidad menor o igual a 0.005 suman probabilidad {0}".format(sum_0005)
    print "\nLa entropia de la fuente es {0}".format(entropia)
    
    archivo.close()
    return entropia

exp = ""
if __name__ == "__main__":
    # ip = [x[4] for x in  scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
    # bdcst = [x[2] for x in  scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]

    tiempo = 60 * 5

    if len(sys.argv) < 2:
        print ''
        print "Usage: " + sys.argv[0] + " <*.cap> <exp>"
        print "\tDonde <exp> puede ser: \"exp-proto\", \"exp-nodos\""
    elif len(sys.argv) > 2:
        archivo = sys.argv[1]
        exp = sys.argv[2]
        if exp == "exp-proto":
            p = sniff(offline = archivo, prn = entropiaEthernet)
            calcularEntropia(types)
        elif exp == "exp-nodos":
            p = sniff(offline = archivo, prn = nodosDistinguidos)
            print "Entropia destino paquetes ARP Who Has"
            calcularEntropia(nodos_dst)
        else:
            print "Experimento invalido"
