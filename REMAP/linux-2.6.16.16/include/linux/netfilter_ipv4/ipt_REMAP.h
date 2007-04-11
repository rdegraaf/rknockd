/* declarations for the iptables REMAP target */

#ifndef IPT_REMAP_H
    #define IPT_REMAP_H
    
    #ifdef __KERNEL__
        #include <linux/types.h>
    #else
        #include <stdint.h>
    #endif
    
    #define REMAP_PROC_FILE "net/netfilter/remap" /* write rules to this file */
    #define REMAP_TIMEOUT 10000   /* lifetime for remap rules in milliseconds */

    /* Format for remap rules to be written to REMAP_PROC_FILE.
    All fields must be in network byte order. */
    struct ipt_remap
    {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint32_t remap_addr;
        uint16_t dst_port;
        uint16_t remap_port;
        uint8_t  proto;
    } __attribute__((__packed__));

#endif /* IPT_REMAP_HJ */
