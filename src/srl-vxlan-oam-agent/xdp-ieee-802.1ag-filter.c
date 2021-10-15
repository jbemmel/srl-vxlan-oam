#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "ieee8021ag.h"

static void swap_src_dst_mac(void *data)
{
	unsigned short *p = data;
	unsigned short dst[3];

	dst[0] = p[0]; dst[1] = p[1]; dst[2] = p[2];
	p[0] = p[3];   p[1] = p[4];	  p[2] = p[5];
	p[3] = dst[0]; p[4] = dst[1];	p[5] = dst[2];
}

static void copy_src_mac_to_dest(void *data)
{
	unsigned short *p = data;

	p[0] = p[3]; p[1] = p[4]; p[2] = p[5];
}

static void swap_src_dst_ip(struct iphdr *ip)
{
  // Note: Swapping does not alter the checksum
  __be32 tmp_ip = ip->saddr;
  ip->saddr = ip->daddr;
  ip->daddr = tmp_ip;
}

static int _process_cfm(struct ethhdr *outer_eth, struct ethhdr *inner_eth, struct iphdr *ip, void *data_end )
{
   if ( (void*) (inner_eth+1) + sizeof(struct cfmhdr) <= data_end ) {

     struct cfmhdr *cfmhdr = (struct cfmhdr *) ((void*) (inner_eth+1));
     switch (cfmhdr->opcode) {
     case CFM_CCM:
       break;

     case CFM_LBM:
       // cfm_send_lbr(ifname, (uint8_t *) data, (int) header->caplen);
       // Can be sent to multicast group -> replace with virtual unique MAC
       if ( ETHER_IS_CCM_GROUP(inner_eth->h_dest) ) {
          copy_src_mac_to_dest( inner_eth );
          outer_eth->h_source[5] ^= inner_eth->h_source[5]; // XOR last byte
       } else {
          swap_src_dst_mac( inner_eth );
       }
       swap_src_dst_mac( outer_eth );
       swap_src_dst_ip( ip );
       cfmhdr->opcode = CFM_LBR;
       return XDP_TX;

     case CFM_LTM:
       /* Linktrace Responder */
       // processLTM(ifname, (uint8_t *) data);
       break;

     default:
       break;
     }
   }
   return XDP_DROP; // too small
}

// SEC("proc")
int vxlan_filter_cfm(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)eth + sizeof(*eth) <= data_end) {

       // Drop frames sent from multicast
       if (ETHER_IS_MCAST(eth->h_source)) return XDP_DROP;

       // TODO if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
       if (eth->h_proto == __constant_htons(ETH_P_IP)) {
            struct iphdr *ip = data + sizeof(*eth);
            if ((void *)ip + sizeof(*ip) <= data_end)
            {
                if (ip->protocol == IPPROTO_UDP)
                {
                    struct udphdr *udp = (void *)ip + sizeof(*ip);
                    if ((void *)udp + sizeof(*udp) <= data_end)
                    {
                        if ( udp->dest == __constant_htons(4789) ) {
                           // Process VXLAN inner packet
                           struct ethhdr *eth2 = (void *)udp + sizeof(*udp);
                           if ((void *)eth2 + sizeof(*eth2) <= data_end) {
                              // Look for Ethernet CFM frames
                              if (eth2->h_proto == __constant_htons(ETYPE_CFM)) {
                                 return _process_cfm( eth, eth2, ip, data_end );
                              }
                           }
                        }
                    }
                }
            }
       }
    }
    return XDP_PASS;
}

// char _license[] SEC("license") = "GPL";
