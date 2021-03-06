# srl-vxlan-oam
Operations, Administration, and Maintenance (OAM) for VXLAN L2 services on SR Linux conceptually based on [IEEE 802.1ag](https://en.wikipedia.org/wiki/IEEE_802.1ag)

# Introduction
Most network engineers are familiar with utilities such as 'ping' and 'traceroute'. However, these tools are only applicable to routed networks like the Internet, and require each endpoint to have an IP address. For operators or infrastructure teams offering L2 overlay services such as EVPN VXLAN based overlays, this may pose a problem.

## Separation of concerns at the L2/L3 demarcation
We commonly take the distinction between L2 and L3 services in stride, and treat them as being one and the same - "the network". 
However, from an operational perspective it can be useful to maintain a clear separation between the two: 
* The L2 Ethernet layer assigns a unique MAC address to each endpoint within a broadcast domain and performs packet forwarding (using point-to-point unicast or point-to-multipoint multicast/broadcast)
* The L3 IP layer deals with IP addresses, subnetting and routing (determining the next hop link and target MAC address, based on the destination IP)

By leaving the assignment and management of IPs as an application level issue that is out of scope, the network team can focus on the basics: L2 reachability and forwarding paths. These OAM tools only deal with L2 MAC addresses out of principle, allowing the users/customers of the network to use whatever IP scheme they concocted (with however many configuration mistakes they make)

## Implementation considerations for physical hardware devices
Datacenter fabrics are built using physical devices, not virtual ones. These appliances have dedicated chips to optimize data plane packet processing, handling most packets in hardware (as opposed to software running on a generic CPU). There is only a small, specific (hardcoded) set of protocols that (can) get forwarded to the generic CPU:
* Control plane protocols like ICMP and BGP/OSPF/ISIS
* Address management protocols like ARP/ND, DHCP

For overlay services, most VXLAN packets are handled fully in hardware, either in dedicated logic (on EVPN leaf nodes) or as generic IP/UDP packets (at spines or other routers). In order to implement custom OAM tooling for VXLAN L2 services, this prototype application uses *custom ICMP packets* using Experimental protocol values as defined in [RFC4727](https://www.rfc-editor.org/rfc/rfc4727.html); because these are ICMP packets, the ASIC on physical hardware is expected to always forward them to the general CPU for processing. And because they are regular IP packets, they follow the same link hashing logic/paths

For this reason, this prototype does not strictly adhere to the IEEE 802.1ag wire format. Some open source implementations (like [this](https://github.com/vnrick/dot1ag-utils) project) exist, but they do not support VXLAN overlay services - and even if they did, real ASICs would likely drop the packets. This is an IEEE 802.1ag implementation "in spirit", using a custom (non-interoperable) wire format.

In summary: This project implements VXLAN L2 OAM tools (ping, tracelink) for overlay networks, using eBPF XDP filters to process/craft custom ICMP packets on SR Linux.

# Traceroute for VXLAN overlays
Out of the box, all Linux systems - including SR Linux - support a 'traceroute' command:
```
A:leaf-3-1.1.0.3# traceroute 1.1.0.4 network-instance default                                                                                                                                                      
Using network instance default
traceroute to 1.1.0.4 (1.1.0.4), 30 hops max, 60 byte packets
 1  192.168.127.10 (192.168.127.10)  11.225 ms * *
 2  192.168.127.0 (192.168.127.0)  10.656 ms * *
 3  192.168.127.13 (192.168.127.13)  9.626 ms * *
 4  1.1.0.4 (1.1.0.4)  14.249 ms  14.169 ms  14.081 ms
```
In this example, the interface IPs for the local leaf, the spine, and the destination leaf are shown, as well as the destination VTEP loopback IP.

## Calling all VTEPs
As a first step, we can automate the initiation of a 'traceroute' towards all VTEPs in a particular VXLAN service.

## Sources used

https://dev.to/satrobit/absolute-beginner-s-guide-to-bcc-xdp-and-ebpf-47oi - sample XDP program
https://github.com/netoptimizer/prototype-kernel/blob/master/kernel/samples/bpf/xdp_ddos01_blacklist_kern.c - sample DDoS program
