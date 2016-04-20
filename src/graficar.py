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
	lista_nodos_dst = []
	total_pkts = 0
	for pkt in p:
		if ARP in pkt and pkt[ARP].op == 1: # who.has
			total_pkts += 1
			dst = pkt[ARP].pdst
			src = pkt[ARP].psrc
			especial = "10.2.0.187"
			if dst == especial:
				print "Fuente de " + especial + " es " + src
			lista_nodos_dst.append(dst)
			inc(edges, (src,dst))
			inc(nodes_dst, dst)

	g = nx.DiGraph()
	for comm, peso in edges.iteritems():
		# g.add_edge(comm[0],comm[1], weight=peso)
		g.add_edge(comm[0],comm[1])

	node_size = []
	for ip in g:
		if ip in nodes_dst:
			size = float(nodes_dst[ip]) / float(total_pkts) * 5000 + 50
			print "IP {0} tiene peso: {1}".format(ip, size)
			node_size.append(size)
		else:
			node_size.append(30)

	print ""
	node_color = []
	node_label = {}
	entropia = calcularEntropia(lista_nodos_dst)
	last_label = 1
	for ip in g:
		if ip in nodes_dst:
			proba = float(nodes_dst[ip])/float(total_pkts)
			info = - math.log(proba)/math.log(2)
			if info < entropia: # si la informacion de la ip es menor de la entropia es distinguido
				node_color.append('red')
				node_label[ip] = last_label
				print "IP {0} tiene informacion: {1}, debajo de la entropia y su label es: {2}".format(ip, info, last_label)
				last_label += 1
			else:
				node_color.append('cyan')
		else:
			node_color.append('cyan')

	graphviz_prog = ['twopi', 'gvcolor', 'wc', 'ccomps', 'tred', 'sccmap', 'fdp', 'circo', 'neato', 'acyclic', 'nop', 'gvpr', 'dot', 'sfdp']
	# grafico
	#pos=nx.spring_layout(g,iterations=100)
	#pos = nx.shell_layout(g)
	pos = graphviz_layout(g,prog='twopi',args='')
	nx.draw(g, pos,
		node_size=node_size,
		node_color=node_color,
		alpha=0.7,
		edge_color='grey',
		arrows=False
		)
	nx.draw_networkx_labels(g, pos, node_label)
	aux = f.split('.')
	plt.savefig(aux[0] + ".png")
