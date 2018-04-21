from scapy.all import *
import netifaces
import argparse
import datetime
conf.sniff_promisc=1
packets={}
def getip(iface):
	if iface in netifaces.interfaces():
		return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']

def printdetect(pkt,packet):
	print datetime.datetime.now(),"DNS poisoning attempt"
	print "TXID",pkt[DNS].id,"Request",pkt[DNSQR].qname[:-1]
	print "Answer1"
	for i in range(0,pkt[DNS].ancount):
		print pkt[DNSRR][i].rdata 
	print "Answer2"
	for i in range(0,packet[DNS].ancount):
		print packet[DNSRR][i].rdata
	print "\n"
	
def detectcallback(interface):
	def dnsdet(pkt):
		#print "in dnsdet"
		#print pkt.show()	
    		if (pkt.haslayer(DNSQR) and pkt[DNS].ancount>=1): # DNS response record
			if pkt[DNS].id in packets.keys():
				if pkt[Ether].src!=packets[pkt[DNS].id][Ether].src:
					printdetect(pkt,packets[pkt[DNS].id])
				else:
					
					for i in range(0,pkt[DNS].ancount):
						if pkt[DNSRR][i].rrname==pkt[DNSQR].qname:
							anpkt=pkt[DNSRR][i]
					for i in range(0,packets[pkt[DNS].id][DNS].ancount):
						if packets[pkt[DNS].id][DNSRR][i].rrname==pkt[DNSQR].qname:
							anpacket=packets[pkt[DNS].id][DNSRR][i]
					if anpkt.ttl!=anpacket.ttl:
						printdetect(pkt,packets[pkt[DNS].id])	
			else:
				packets[pkt[DNS].id] = pkt
				
			
	return dnsdet


parser=argparse.ArgumentParser(add_help=False)
parser.add_argument('-i',help='interface name')
parser.add_argument('-r',help='pcap trace file')
parser.add_argument('expression',help='BPF filter expression')
args=parser.parse_args()
if args.i:
	interface = args.i	
else:
	interface=netifaces.gateways()['default'][netifaces.AF_INET][1]
if args.expression:
	filterexpr='udp port 53 and ' + args.expression
else:
	filterexpr='udp port 53'	
if args.r:
	sniff(filter=filterexpr, offline=args.r, prn=detectcallback(interface))
else:
	sniff(filter=filterexpr, iface=interface, store=0, prn=detectcallback(interface))	
