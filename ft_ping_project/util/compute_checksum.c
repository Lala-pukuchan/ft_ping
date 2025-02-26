#include "compute_checksum.h"

unsigned short compute_checksum(void *buf, int len) {
    unsigned short *data = buf;
    unsigned int sum = 0;
    
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    
    if (len == 1) {
        unsigned short last_byte = 0;
        *((unsigned char *)&last_byte) = *(unsigned char *)data;
        sum += last_byte;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return (unsigned short)(~sum);
} 