#!/usr/bin/python3

#
# UDP traceroute utility to check reachability and measure RTT between routers
# (e.g. VXLAN VTEP loopback IPs) across all uplinks and available paths
#
# Sends out UDP packets with destination ports in the range 33434-33464
# (as allowed by SR Linux in the default config). The port is incremented for
# every next hop (max TTL=n), and for every packet to that next hop (probes-per-hop=3)
#
# Assumes this is being run in srbase-default namespace (however its name)
#
# See also: https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/traceroute/index.html
#

import socket, sys, re, os, netns, logging, ipaddress, json
from datetime import datetime, timezone
from scapy.layers.inet import IP, UDP, ICMP, traceroute
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.sendrecv import srp # send/recv at Layer2
from scapy.layers.l2 import getmacbyip, Ether

if len(sys.argv) < 5:
    print( f"Usage: {sys.argv[0]} <local VTEP IP> <entropy> <list of uplink devices separated by ','> <list of VTEP IPs separated by ','> [debug]" )
    sys.exit(1)

LOCAL_VTEP = sys.argv[1]
ENTROPY = int(sys.argv[2])
UPLINKS = sys.argv[3].split(",")
VTEP_IPs = sys.argv[4].split(",")

DEBUG = ('DEBUG' in os.environ and bool( os.environ['DEBUG'] )
         or (len(sys.argv)==6 and sys.argv[5]=="debug") )
SRL_C = os.path.exists('/.dockerenv')
logging.basicConfig(
  filename='/var/log/srlinux/stdout/ecmp-traceroute.log',
  format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s',
  datefmt='%H:%M:%S',
  level=logging.DEBUG if DEBUG else logging.INFO)

logging.info( f"Command: {sys.argv}" )
if DEBUG:
    print( f"Containerized SRL:{SRL_C}" )

# Use scapy

# Needs to run in srbase-default netns
uplink_addr = {}
with netns.NetNS(nsname="srbase-default"):
 for uplink in UPLINKS:
    local_ip = get_if_addr(uplink)
    local_mac = get_if_hwaddr(uplink)
    d = int(local_ip[-1])
    peer_ip = local_ip[:-1] + str( (d-1) if (d%2) else (d+1) )
    peer_mac = getmacbyip(peer_ip) # "No route" warning
    if DEBUG:
        print( f"Uplink: {uplink} ip={local_ip} mac={local_mac} peer={peer_ip} mac={peer_mac}" )
    uplink_addr[uplink] = { 'src_mac': local_mac, 'dst_mac': peer_mac }

IANA_TRACERT_PORT = 33434

# Cannot use this API - we want to pick the outgoing interface
# ans,unans = traceroute(VTEP_IPs[0],l4=UDP(sport=1234,dport=IANA_TRACEROUTE_PORT)/"xxx")
# print( ans, unans )
# ans.summary( lambda s,r : r.sprintf("%IP.src%\t{UDP:%UDP.sport%}") )
results = {} # Indexed by VTEP
done = {}
with netns.NetNS(nsname="srbase"):
 for ttl in range(1,4):
  for u,uplink in enumerate(UPLINKS):
   base_if = uplink.split('.')[0]
   macs = uplink_addr[ uplink ]
   l2 = Ether(src=macs['src_mac'],dst=macs['dst_mac'])
   for vtep in VTEP_IPs:
     # Skip if reached
     if vtep in done:
         continue

     # Hash entropy is different for different VTEP dest IPs (assume unique ips)
     l3 = IP(src=LOCAL_VTEP,dst=vtep,ttl=ttl,flags="DF") # can set ID, ToS

     # All uplinks go to the same final endpoint, vary the path entropy
     udp_src = 1 + (49999 + u + ENTROPY) % 65534

     #
     # Paris-traceroute and Dublin-traceroute manipulate the content/UDP checksum
     # to overcome certain flaws in Internet routers. Assuming we don't need that
     # here
     #
     l4 = UDP(sport=udp_src,dport=(IANA_TRACERT_PORT,
                                   IANA_TRACERT_PORT + min(1,ttl-1) ))
     trace_pkts = l2/l3/l4/"SRLinux"
     # sendp(tracert_pkts, iface=base_if)
     filter = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12))"
     # Need a timeout for intermediate hops, else they don't respond
     ans, unans = srp(trace_pkts, iface=base_if, verbose=DEBUG, filter=filter, timeout=1, retry=1)
     if DEBUG:
         print( ans, unans )
         ans.summary( lambda s,r : r.sprintf("%IP.src% ttl=%IP.ttl%\t{ICMP:%ICMP.type%}") )
         # ans.summary( lambda s,r : print( r.show(dump=True) ) )
         ans.summary( lambda s,r : print( f"sent={s.sent_time} t={s.time} rx={r.time} rtt={(r.time - s.sent_time) * 1000 :.2f}ms" ) )

     next_hops = {}
     reached = False
     for s,r in ans:
         next_hop = r[IP].src
         rtt = int( (r.time - s.sent_time) * 1e06 ) # in us
         if next_hop in next_hops:
             next_hops[ next_hop ].append( rtt )
         else:
             next_hops[ next_hop ] = [rtt]
         # Type 11 == TTL zero for intermediate hops
         if r[ICMP].type == 3: # Destination port unreachable, i.e. endpoint
            rtts = next_hops[ next_hop ]
            avg_rtt = sum(rtts)/len(rtts)
            done[ vtep ] = { 'hops': ttl, 'probes': len(rtts), 'avg_rtt_in_ms': 1000 * avg_rtt }

     if vtep in results:
        results[vtep][ttl] = next_hops
     else:
        results[vtep] = { ttl: next_hops }

print( json.dumps(results) )
if DEBUG:
    print( done )
sys.exit(0)
