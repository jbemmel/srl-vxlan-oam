#!/bin/sh

# Exclude TTL=0 ICMP errors from rate limiting by the kernel, default = 6168
echo "JvB updating icmp_ratemask to 4120 at `date` as `whoami`" >> /var/log/srlinux/jvb_sysctl.log
cat /proc/sys/net/ipv4/icmp_ratemask >> /var/log/srlinux/jvb_sysctl.log
sysctl -w net.ipv4.icmp_ratemask=4120
echo "Result: $?" >> /var/log/srlinux/jvb_sysctl.log
