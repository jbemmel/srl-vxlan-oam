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

import sys, os, logging, ipaddress, json # netns
from scapy.layers.inet import IP, UDP, ICMP, traceroute
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.sendrecv import srp # send/recv at Layer2
from scapy.layers.l2 import getmacbyip, Ether
from scapy.interfaces import resolve_iface
from scapy.data import ETH_P_ALL

if len(sys.argv) < 7:
    print( f"Usage: {sys.argv[0]} <local VTEP IP[/prefix]> <ttl range> <timeout(s)> <entropy> <list of uplink devices separated by ','> <list of VTEP IPs separated by ','> [debug]" )
    sys.exit(1)

LOCAL_VTEP = sys.argv[1]
TTL_RANGE = sys.argv[2] # e.g. 1-3, inclusive
TIMEOUT_IN = sys.argv[3]
ENTROPY = int(sys.argv[4])
UPLINKS = sys.argv[5].split(",")
VTEP_IPs = sys.argv[6].split(",")

DEBUG = ('DEBUG' in os.environ and bool( os.environ['DEBUG'] )
         or (len(sys.argv)==8 and sys.argv[7]=="debug") )

SRL_C = os.path.exists('/.dockerenv')
logging.basicConfig(
  filename='/var/log/srlinux/stdout/ecmp-traceroute.log',
  format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s',
  datefmt='%H:%M:%S',
  level=logging.DEBUG if DEBUG else logging.INFO)

if '/' in LOCAL_VTEP:
    src_ips = [str(ip) for ip in ipaddress.IPv4Network(LOCAL_VTEP,strict=False)]
else:
    src_ips = [ LOCAL_VTEP ]

if TIMEOUT_IN=="auto":
    # with open('/proc/sys/net/ipv4/icmp_ratemask','r') as icmp_ratemask:
    #     ratemask = int( icmp_ratemask.read() )
    # if (ratemask & 2048) != 0: # Affects TTL=0 errors?
    #   with open('/proc/sys/net/ipv4/icmp_ratelimit','r') as icmp_ratelimit: # ms
    #     TIMEOUT = int( icmp_ratelimit.read() ) / 1000.0
    # else:
    #     print( "Using auto-selected 1s interval between packets", file=sys.stderr )
    TIMEOUT = 1.0 # Default 1pps
else:
    TIMEOUT = float(TIMEOUT_IN)

logging.info( f"Command: {sys.argv} TIMEOUT={TIMEOUT}" )
if DEBUG:
    print( f"Containerized SRL:{SRL_C}" )

if TIMEOUT<1.0:
    print( f"Many routers rate-limit ICMP replies to 1/sec, consider increasing {TIMEOUT} to minimum interval=1s (or 'auto') to avoid", file=sys.stderr )
    # TIMEOUT = 1.0

# Use scapy

# Needs to run in srbase-default netns, assume caller takes care of that
uplink_addr = {}
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

# Need to listen for ICMP replies on every uplink
# When using source IPs that are not provisioned on interfaces, need to listen
# in 'srbase' NetNS
uplink_socks = {}
# with netns.NetNS(nsname="srbase"):
filter = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12))"
for uplink in UPLINKS:
   iface = resolve_iface( uplink ) # Remove ".x" subinterface: .split('.')[0]
   s = iface.l2socket()(iface=iface,filter=filter,type=ETH_P_ALL)
   uplink_socks[ s ] = uplink

ttl_min, ttl_max = map(int, TTL_RANGE.split('-'))
id = 0
for ttl in range(ttl_min,ttl_max+1):
  for u,uplink in enumerate(UPLINKS):
   macs = uplink_addr[ uplink ]
   l2 = Ether(src=macs['src_mac'],dst=macs['dst_mac'])
   for vtep in VTEP_IPs:
     # Skip if reached
     if vtep in done:
         continue

     # Hash entropy is different for different VTEP dest IPs (assume unique ips)
     id += 1 # Each packet needs unique, reproducable ID

     # Vary source IPs too, if available
     src_ip = src_ips[ id % len(src_ips) ]
     l3 = IP(src=src_ip,dst=vtep,ttl=ttl,id=id,flags="DF") # Could set ToS

     # All uplinks go to the same final endpoint, vary the path entropy
     # by picking different UDP source ports in the dynamic/private port
     # range 49152-65535
     udp_src_lo = 49152 + (u + ENTROPY) % (65536-49152)
     udp_src_hi = 49152 + (u + ENTROPY + min(1,ttl-1)) % (65536-49152)

     #
     # Paris-traceroute and Dublin-traceroute manipulate the content/UDP checksum
     # to overcome certain flaws in Internet routers. Assuming we don't need that
     # here
     #
     # Some VTEPs (e.g. Cumulus) only allow destination port 33434, only vary
     # UDP source port
     l4 = UDP(sport=(udp_src_lo,udp_src_hi),dport=IANA_TRACERT_PORT)
     trace_pkts = l2/l3/l4/"SRLinux"

     # Add 500ms interval to avoid rate limiting on unlicensed SRL? Slows down everything
     # ans = srp1()
     logging.info( f"Sending {udp_src_hi-udp_src_lo+1} packets to {vtep} TTL={ttl}" )

     #
     # Cannot send too fast, routers rate-limit ICMP responses to 1/sec at most
     # (per source IP)
     #
     ans, unans = srp(trace_pkts, iface=uplink, verbose=DEBUG, inter=TIMEOUT,
                rcv_pks=uplink_socks,timeout=2*TIMEOUT,retry=0)
     logging.info( f"Got responses: {ans} no answer={unans}" )
     if DEBUG:
         print( f"TTL={ttl} {uplink} VTEP={vtep}: Answers: {ans} missing: {unans}" )
         ans.summary( lambda s,r : r.sprintf("%IP.src% ttl=%IP.ttl%\t{ICMP:%ICMP.type%}") )
         if len(unans)>0:
            print( f"Missing reply(s) on {uplink}:" )
            unans.summary( lambda s : print( s.show(dump=True) ) )
         ans.summary( lambda s,r : print( f"sniffed_on={r.sniffed_on} rtt={(r.time - s.sent_time) * 1000 :.2f}ms" ) )

     next_hops = { f'{uplink}-no-reply': len(unans), f'{uplink}-sent': udp_src_hi-udp_src_lo+1 }
     for s,r in ans:
         next_hop = r[IP].src
         rtt = int( (r.time - s.sent_time) * 1e06 ) # in us
         entry = { 'rtt': rtt, 'tx': uplink, 'rx': r.sniffed_on }
         if next_hop in next_hops:
             next_hops[ next_hop ].append( entry )
         else:
             next_hops[ next_hop ] = [ entry ]
         # Type 11 == TTL zero for intermediate hops
         if r[ICMP].type == 3: # Destination port unreachable, i.e. endpoint
            rtts = next_hops[ next_hop ]
            avg_rtt = sum([e['rtt'] for e in rtts ])/len(rtts)
            done[ vtep ] = { 'hops': ttl, 'probes': len(rtts), 'avg_rtt_in_us': avg_rtt }

     if vtep in results:
        if ttl in results[vtep]:
           for k,v in next_hops.items():
              if k in results[vtep][ttl]:
                 results[vtep][ttl][k].extend( v )
              else:
                 results[vtep][ttl][k] = v
        else:
           results[vtep][ttl] = next_hops
     else:
        results[vtep] = { ttl: next_hops, 'no-reply-total' : { i : 0 for i in UPLINKS } }
     results[vtep]['no-reply-total'][uplink] += len(unans)

# Done
for s in uplink_socks:
    s.close()

print( json.dumps(results) )
if DEBUG:
    print( done )
sys.exit(0)
