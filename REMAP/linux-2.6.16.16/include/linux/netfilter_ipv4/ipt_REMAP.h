#ifndef IPT_REMAP_H
    #define IPT_REMAP_H
    
    #ifdef __KERNEL__
        #include <linux/types.h>
    #else
        #include <stdint.h>
    #endif
    
    #define REMAP_PROC_FILE "net/netfilter/remap"
    
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
