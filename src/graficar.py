#! /usr/bin/env python
import sys
from scapy.all import *
import networkx as nx
from networkx.drawing.nx_agraph import graphviz_layout
import matplotlib.pyplot as plt
from operator import itemgetter
from process import calcularEntropia

def inc(dic, key):
	if key not in dic:
		dic[key] = 1
	else:
		dic[key] = dic[key] + 1

if __name__ == "__main__":

	if( len(sys.argv) < 2 ):
		print 'Hace falta un archivo con formato .pcap'
		sys.exit()

	f = sys.argv[1]

	p = sniff(offline = f)

	edges = {}
	nodes_dst = {}
	nodes_src = {}
	lista_nodos_dst = []
	total_pkts = 0
	for pkt in p:
		if ARP in pkt and pkt[ARP].op == 1: # who.has
			total_pkts += 1
			dst = pkt[ARP].pdst
			src = pkt[ARP].psrc
			lista_nodos_dst.append(dst)
			inc(edges, (src,dst))
			inc(nodes_dst, dst)
			inc(nodes_src, src)

	g = nx.DiGraph()
	for comm, peso in edges.iteritems():
		# g.add_edge(comm[0],comm[1], weight=peso)
		g.add_edge(comm[0],comm[1])

	node_size = []
	for ip in g:
		if ip in nodes_dst:
			size = float(nodes_dst[ip]) / float(total_pkts) * 5000 + 50
			print size
			node_size.append(size)
		else:
			node_size.append(30)

	node_color = []
	entropia = calcularEntropia(lista_nodos_dst)
	for ip in g:
		if ip in nodes_dst:
			proba = float(nodes_dst[ip])/float(total_pkts)
			info = proba * (- math.log(proba)/math.log(2))
			if info < entropia: # si la informacion de la ip es menor de la entropia es distinguido
				node_color.append(1)
			else:
				node_color.append(0)
		else:
			node_color.append(0)

	graphviz_prog = ['twopi', 'gvcolor', 'wc', 'ccomps', 'tred', 'sccmap', 'fdp', 'circo', 'neato', 'acyclic', 'nop', 'gvpr', 'dot', 'sfdp']
	# grafico
	#pos=nx.spring_layout(g,iterations=100)
	#pos = nx.shell_layout(g)
	pos = graphviz_layout(g,prog='twopi',args='')
	nx.draw(g, pos,
		node_size=node_size,
		node_color=node_color,
		alpha=0.7,
		edge_color='g'
		)
	plt.show()
