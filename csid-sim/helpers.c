//
// Created by aalston on 10/9/21.
//
#include "helpers.h"

// Helper function to dump memory at location ptr with length len in wireshark importable format
void dump_ptr(void *ptr, int len)
{
    char ret_print[18];
    printf("%06x\t", 0);
    for (int p = 0; p < len; p++) {
        if ((p + 1) % 16 == 0)
            snprintf(ret_print, 18, "\n%06x\t", p + 1);
        printf("%02x%s", *(uint8_t *) (ptr + p), ((p + 1) % 16 == 0) ? ret_print : " ");
    }
    printf("\n\n");
    fflush(stdout);
}

// Calculate the UDP checksum
__u16 calc_checksum(const struct udphdr *hdr, const __u8 *payload, int payload_size)
{
    uint32_t sum = 0;
    uint16_t odd_byte;
    void *buffer = calloc(1, sizeof(struct udphdr)+payload_size);
    memcpy(buffer, hdr, sizeof(*hdr));
    memcpy(buffer+sizeof(*hdr), payload, payload_size);
    __u16 *udph = buffer;
    int len = payload_size+(int)sizeof(*hdr);
    int offset = 0;

    while (len > 1) {
        offset+=2;
        sum += *udph++;
        len -= 2;
    }

    if (len == 1) {
        *(uint8_t*)(&odd_byte) = * (uint8_t*)udph;
        sum += odd_byte;
    }

    sum =  (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    free(buffer);
    return (__u16)~sum;
}
