# srl-vxlan-oam
Operations, Administration, and Maintenance (OAM) for VXLAN L2 services on SR Linux based on IEEE 802.1ag

# Introduction
Most network engineers are familiar with 'ping' and 'traceroute' utilities. However, these tools are only applicable to routed networks like the Internet, and require each endpoint to have an IP address. For operators offering L2 overlay services such as EVPN VXLAN based overlays, this may not be applicable.

Some open source implementations (like [this](https://github.com/vnrick/dot1ag-utils) project) exist, but they do not support VXLAN overlay services.

This project implements VXLAN L2 OAM tools (ping, tracelink) for overlay networks, using eBPF XDP filters on SR Linux

## Sources used

https://dev.to/satrobit/absolute-beginner-s-guide-to-bcc-xdp-and-ebpf-47oi - sample XDP program
https://github.com/netoptimizer/prototype-kernel/blob/master/kernel/samples/bpf/xdp_ddos01_blacklist_kern.c - sample DDoS program
