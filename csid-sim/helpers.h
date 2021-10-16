//
// Created by aalston on 10/9/21.
//

#include <stdio.h>
#include <string.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <asm-generic/types.h>
#include <linux/seg6.h>


void dump_ptr(void *ptr, int len);
__u16 calc_checksum(const struct udphdr *hdr, const __u8 *payload, int payload_size);