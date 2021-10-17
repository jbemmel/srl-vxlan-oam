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

import socket, sys, re, os, netns, selectors, logging, ipaddress
from datetime import datetime, timezone
from scapy.layers.inet import IP, UDP, ICMP, traceroute
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.sendrecv import srp # send/recv at Layer2
from scapy.layers.l2 import getmacbyip, Ether

if len(sys.argv) < 5:
    print( f"Usage: {sys.argv[0]} <local VTEP IP> <entropy> <list of uplink devices separated by ','> <list of VTEP IPs separated by ','>" )
    sys.exit(1)

LOCAL_VTEP = sys.argv[1]
ENTROPY = int(sys.argv[2])
UPLINKS = sys.argv[3].split(",")
VTEP_IPs = sys.argv[4].split(",")

DEBUG = 'DEBUG' in os.environ and bool( os.environ['DEBUG'] )
SRL_C = os.path.exists('/.dockerenv')
logging.basicConfig(
  filename='/var/log/srlinux/stdout/ecmp-traceroute.log',
  format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s',
  datefmt='%H:%M:%S',
  level=logging.DEBUG if DEBUG else logging.INFO)

logging.info( f"Command: {sys.argv}" )
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
    peer_mac = getmacbyip(peer_ip)
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
     # Skip if TTL reached
     if vtep in done:
         continue

     # Hash entropy is different for different VTEPs
     l3 = IP(src=LOCAL_VTEP,dst=vtep,ttl=ttl) # can set ID, DF, ToS

     # All uplinks go to the same final endpoint, vary the path entropy
     udp_src = 1 + (49999 + u + ENTROPY) % 65534
     l4 = UDP(sport=udp_src,dport=(IANA_TRACERT_PORT,IANA_TRACERT_PORT+ttl-1))
     trace_pkts = l2/l3/l4/"xxx"
     # sendp(tracert_pkts, iface=base_if)
     filter = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12))"
     # Need a timeout for intermediate hops, else they don't respond
     ans, unans = srp(trace_pkts, iface=base_if, verbose=True, filter=filter, timeout=1, retry=1)
     print( ans, unans )
     ans.summary( lambda s,r : r.sprintf("%IP.src% ttl=%IP.ttl%\t{UDP:%UDP.sport%}") )
     ans.summary( lambda s,r : print( r.show(dump=True) ) )
     ans.summary( lambda s,r : print( f"sent={s.sent_time} t={s.time} rx={r.time} rtt={(r.time - s.sent_time) * 1000 :.2f}ms" ) )

     rtts = [ (r.time - s.sent_time) for s,r in ans ]
     if vtep in results:
        results[vtep][ttl] = rtts
     else:
        results[vtep] = { ttl: rtts }

     ttl_zeros = [ r for s,r in ans if r[ICMP].type == 11 ]
     if ttl_zeros == []:
        avg_rtt = 1000 * sum(rtts)/len(rtts) if rtts!=[] else 0
        done[ vtep ] = { 'hops': ttl, 'avg_rtt_in_ms': avg_rtt }

print( done )
sys.exit(0)
