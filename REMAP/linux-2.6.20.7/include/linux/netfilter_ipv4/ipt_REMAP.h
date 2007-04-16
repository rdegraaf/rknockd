/* declarations for the iptables REMAP target */

#ifndef IPT_REMAP_H
    #define IPT_REMAP_H
    
    #ifdef __KERNEL__
        #include <linux/types.h>
    #else
        #include <stdint.h>
    #endif
    
    #define REMAP_PROC_FILE "net/netfilter/remap" /* write rules to this file */

    /* Format for remap rules to be written to REMAP_PROC_FILE. 
    All fields must be in network byte order. */
    struct ipt_remap
    {
        uint32_t src_addr;  /* connection source IP address */
        uint32_t dst_addr;  /* connection destination IP address */
        uint32_t remap_addr;/* redirect to this IP address */
        uint16_t dst_port;  /* connection destination port */
        uint16_t remap_port;/* redirect to this port */
        uint8_t  proto;     /* protocol number (see /etc/protocols) */
        uint8_t _pad;
        uint16_t ttl;       /* rule lifetime (milliseconds) */
    } __attribute__((__packed__));

#endif /* IPT_REMAP_HJ */
