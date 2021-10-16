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
from scapy.layers.inet import UDP, traceroute

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
IANA_TRACEROUTE_PORT = 33434
ans,unans = traceroute(VTEP_IPs[0],l4=UDP(sport=1234,dport=IANA_TRACEROUTE_PORT)/"xxx")
print( ans, unans )
ans.summary( lambda s,r : r.sprintf("%IP.src%\t{UDP:%UDP.sport%}") )
sys.exit(0)
