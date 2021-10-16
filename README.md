# srl-vxlan-oam
Operations, Administration, and Maintenance (OAM) for VXLAN L2 services on SR Linux based on [IEEE 802.1ag](https://en.wikipedia.org/wiki/IEEE_802.1ag)

# Introduction
Most network engineers are familiar with utilities such as 'ping' and 'traceroute'. However, these tools are only applicable to routed networks like the Internet, and require each endpoint to have an IP address. For operators or infrastructure teams offering L2 overlay services such as EVPN VXLAN based overlays, this may not be applicable.

## Separation of concerns at the L2/L3 demarcation
We commonly take the distinction between L2 and L3 services in stride, and treat them as being one and the same - "the network". 
However, from an operational perspective it can be useful to maintain a clear separation between the two: 
* The L2 Ethernet layer assigns a unique MAC address to each endpoint within a broadcast domain and performs packet forwarding (using point-to-point unicast or point-to-multipoint multicast/broadcast)
* The L3 IP layer deals with IP addresses, subnetting and routing (determining the next hop link and target MAC address, based on the destination IP)

By leaving the assignment and management of IPs as an application level issue that is out of scope, the network team can focus on the basics: L2 reachability and forwarding paths

## Implementation considerations for physical hardware devices
Datacenter fabrics are built using physical devices, not virtual ones. These appliances have dedicated chips to optimize data plane packet processing, handling most packets in hardware (as opposed to software running on a generic CPU). There is only a small, specific (hardcoded) set of protocols that (can) get forwarded to the generic CPU:
* Control plane protocols like BGP/OSPF/ISIS
* Address management protocols like ARP/ND, DHCP

For overlay services, most VXLAN packets are handled fully in hardware, either in dedicated logic (on EVPN leaf nodes) or as generic IP/UDP packets (at spines or other routers). In order to implement custom OAM tooling for VXLAN L2 services, this prototype application uses *custom ARP packets* using the Experimental opcodes 24 and 25 as defined in [RFC5494](https://datatracker.ietf.org/doc/html/rfc5494); because these are ARP packets, the ASIC on physical hardware is expected to always forward them to the general CPU for processing.

Some open source implementations (like [this](https://github.com/vnrick/dot1ag-utils) project) exist, but they do not support VXLAN overlay services.

This project implements VXLAN L2 OAM tools (ping, tracelink) for overlay networks, using eBPF XDP filters on SR Linux

## Sources used

https://dev.to/satrobit/absolute-beginner-s-guide-to-bcc-xdp-and-ebpf-47oi - sample XDP program
https://github.com/netoptimizer/prototype-kernel/blob/master/kernel/samples/bpf/xdp_ddos01_blacklist_kern.c - sample DDoS program
