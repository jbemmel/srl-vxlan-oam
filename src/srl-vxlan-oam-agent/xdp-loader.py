#!/usr/bin/env python3
# coding=utf-8

from bcc import BPF
import netns
import time

device = "e1-1"
# bpf = BPF(text=f"""
# // Can include params like this: #define SRC_MAC {MAC}
# #include "xdp-ieee-802.1ag-filter.c"
# """)
bpf = BPF(src_file="xdp-ieee-802.1ag-filter.c")
vxlan_filter_cfm = b.load_func("vxlan_filter_cfm", BPF.XDP)

with netns.NetNS(nsname="srbase"):
  bpf.attach_xdp(device, vxlan_filter_cfm, 0)

try:
  bpf.trace_print()
except KeyboardInterrupt:
  pass

bpf.remove_xdp(device, 0)
