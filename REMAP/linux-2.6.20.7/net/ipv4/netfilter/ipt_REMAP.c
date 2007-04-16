/* 
 * iptables REMAP target.  
 * $Id$
 *
 * Redirects connections matching given (protocol, src addr, dst addr, dst
 * port) tuples to new destination addresses and ports, according to rules
 * supplied from userspace.  Rules are written to REMAP_PROC_FILE as messages
 * of type struct ipt_remap, apply only to the first matching connection, and
 * are valid for at most rule.ttl milliseconds. 
 *
 * (C) 2007 Rennie deGraaf <degraaf@cpsc.ucalgary.ca>
 *
 * This program is free software; you may redistribute and/or modify
 * it under the terms of the GNU General Public Licence version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/proc_fs.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <asm/uaccess.h>
#include <asm/string.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_REMAP.h>

#define DEBUG

#ifdef DEBUG
    #define PRINTD(x, args ...) printk(KERN_DEBUG "ipt_REMAP: " x, ##args)
#else
    #define PRINTD(x, args ...)
#endif


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rennie deGraaf <degraaf@cpsc.ucalgary.ca>");
MODULE_DESCRIPTION("iptables REMAP target");
MODULE_VERSION("0.1");

#define DEFAULT_REMAP_TIMEOUT 10000  /* default lifetime for remap rules (ms) */
#define REMAP_HASH_BITS 7       /* log of the size of remap_hash_table */

/* type of objects in remap_hash_table */
struct remap_hash_entry
{
    struct ipt_remap rule;
    unsigned long expires;
};

/* data structures for the remap hash table */
static struct remap_hash_entry remap_hash_table[1<<REMAP_HASH_BITS];
static unsigned long remap_hash_collisions = 0;
static unsigned remap_hash_count = 0;
static struct timer_list remap_hash_timer;
static spinlock_t remap_hash_lock = SPIN_LOCK_UNLOCKED;

/* data structures for REMAP_PROC_FILE */
static struct proc_dir_entry* proc_remap = NULL;


/* Garbage collector for the remap hash table 
Iterate over all remap rules, and remove any that have timed out. */
static void
remap_hash_gc(unsigned long data)
{
    unsigned i;
    unsigned long next = jiffies + msecs_to_jiffies(65535); /* maximum possible ttl */
    
    
    spin_lock_bh(&remap_hash_lock);
    
    /* remove expired entries */
    for (i=0; i<(1<<REMAP_HASH_BITS); i++)
    {
        /* only check buckets that are in use */
        if (remap_hash_table[i].rule.src_addr != 0)
        {
            if (time_after_eq(jiffies, remap_hash_table[i].expires))
            {
                PRINTD("garbage collector: deleting entry\n");
                memset(&remap_hash_table[i], 0, sizeof(remap_hash_table[i]));
                remap_hash_count--;
            }
            else if (time_before(remap_hash_table[i].expires, next))
            {
                next = remap_hash_table[i].expires;
            }
        }
    }

    /* schedule a new gc run */
    if ((remap_hash_count > 0) && (time_after(next, jiffies)))
    {
        PRINTD("garbage collector: rescheduling\n");
        remap_hash_timer.expires = next;
        add_timer(&remap_hash_timer);
    }
    
    spin_unlock_bh(&remap_hash_lock);
}


/* Constructor for the remap hash table 
Initialize all related data structures.  */
static void 
remap_hash_init(void)
{
    spin_lock_bh(&remap_hash_lock);
    
    memset(remap_hash_table, 0, sizeof(remap_hash_table));
    remap_hash_collisions = 0;
    remap_hash_count = 0;
    init_timer(&remap_hash_timer);
    remap_hash_timer.function = remap_hash_gc;
    
    spin_unlock_bh(&remap_hash_lock);
    
    PRINTD("hash table initialized: %u entries, %u bytes total\n", 
           1<<REMAP_HASH_BITS, sizeof(remap_hash_table));
}


/* Destructor for the remap hash table 
Cancel any pending garbage collector.  The table itself is static, so it doesn't
need to be freed. */
static void 
remap_hash_fini(void)
{
    /* cancel the garbage collector */
    if (timer_pending(&remap_hash_timer))
        del_timer(&remap_hash_timer);
}


/* Hash function for remap rules
Hashes the original address and protocol fields; remap addresses are not 
covered */
static inline unsigned 
remap_hash_fn(const struct ipt_remap* rule)
{
    return hash_long(rule->src_addr, REMAP_HASH_BITS)
         ^ hash_long(rule->dst_addr, REMAP_HASH_BITS)
         ^ hash_long(rule->dst_port, REMAP_HASH_BITS)
         ^ hash_long(rule->proto, REMAP_HASH_BITS);
}


/* Compares two remap rules
If the rules' original addresses and protocols are the same, return 1.  
Otherwise, return 0 */
static inline int
remap_hash_compare(const struct ipt_remap* a, const struct ipt_remap* b)
{
    if ((b->src_addr == a->src_addr) && (b->dst_addr == a->dst_addr)
        && (b->dst_port == a->dst_port) && (b->proto == a->proto))
        return 1;
    else
        return 0;
}


/* Insert a remap rule into the hash table 
If appropriate, schedule the garbage collector to remove it.
Returns:  0 on success
          -EINVAL if the rule isn't valid
          -ENOSPC if the hash table is full
          -EEXIST if the rule is the same as an existing rule */
static int 
remap_hash_insert(const struct ipt_remap* rule)
{
    unsigned hash;
    
    /* make sure that the rule is valid */
    if ((rule->src_addr == 0) || (rule->dst_addr == 0) || (rule->dst_port == 0)
        || ((rule->remap_addr == 0) && (rule->remap_port == 0)))
        return -EINVAL;
    
    hash = remap_hash_fn(rule);

    spin_lock_bh(&remap_hash_lock);
    
    /* check for overflow */
    if (remap_hash_count == (1<<REMAP_HASH_BITS))
    {
        printk(KERN_WARNING "ipt_REMAP: hash table full; dropping rule\n");
        spin_unlock_bh(&remap_hash_lock);
        return -ENOSPC;
    }
        
    /* find an empty slot, using linear probing */
    while (remap_hash_table[hash].rule.src_addr != 0)
    {
        /* check for duplicates */
        if (remap_hash_compare(rule, &remap_hash_table[hash].rule))
        {
            spin_unlock_bh(&remap_hash_lock);
            return -EEXIST;
        }
        
        /* advance to the next */
        remap_hash_collisions++;
        hash = (hash+1) & ((1<<REMAP_HASH_BITS)-1);
    }
    
    /* insert the rule */
    memcpy(&remap_hash_table[hash].rule, rule, sizeof(struct ipt_remap));
    remap_hash_table[hash].expires = jiffies + msecs_to_jiffies(((rule->ttl==0) ? DEFAULT_REMAP_TIMEOUT : ntohs(rule->ttl)));
    remap_hash_count++;
    
    /* schedule the garbage collector */
    /* if the table is empty, then the gc must be scheduled */
    if ((remap_hash_count == 1) || (time_before(remap_hash_table[hash].expires, 
                                                remap_hash_timer.expires)))
    {
        if (timer_pending(&remap_hash_timer))
            del_timer(&remap_hash_timer);
        remap_hash_timer.expires = remap_hash_table[hash].expires;
        add_timer(&remap_hash_timer);
    }
    
    spin_unlock_bh(&remap_hash_lock);

    return 0;
}


/* Retrieve a remap rule from the hash table
If a rule matching *rule exists in the hash table, copy it into *rule, remove it
from the table, and return 0.  Otherwise, return 1.  If this was the last rule 
in the table, cancel any pending garbage collector.
All fields in *rule used by remap_hash_fn() must be set before this function is 
called.  Other fields will be overwritten on successful return. */
static int
remap_hash_remove(struct ipt_remap* rule)
{
    unsigned hash;
    int count = 0;
    
    hash = remap_hash_fn(rule);
    
    spin_lock_bh(&remap_hash_lock);

    /* check for underflow */
    if (remap_hash_count == 0)
    {
        spin_unlock_bh(&remap_hash_lock);
        return -ENOENT;
    }

    /* search the table, using linear probing */
    /* an empty bucket or overflow means that the rule isn't in the table */
    while ((remap_hash_table[hash].rule.src_addr != 0) 
           && (count < (1<<REMAP_HASH_BITS)))
    {
        /* check for a match */
        if (remap_hash_compare(rule, &remap_hash_table[hash].rule))
        {
            /* copy the value back to the caller */
            rule->remap_addr = remap_hash_table[hash].rule.remap_addr;
            rule->remap_port = remap_hash_table[hash].rule.remap_port;
            
            /* clear the entry */
            memset(&remap_hash_table[hash], 0, sizeof(remap_hash_table[hash]));
            remap_hash_count--;
            
            /* if this was the last entry, cancel the garbage collector */
            if ((remap_hash_count == 0) && timer_pending(&remap_hash_timer))
                del_timer(&remap_hash_timer);
            
            spin_unlock_bh(&remap_hash_lock);
            return 0;
        }
        
        /* advance to the next */
        count++;
        hash = (hash+1) & ((1<<REMAP_HASH_BITS)-1);
    }

    spin_unlock_bh(&remap_hash_lock);
    
    /* no match */
    return -ENOENT;
}


/* Print a remap rule 
When debug mode is enabled, print a remap rule to the kernel log */
static inline int 
print_rule(const struct ipt_remap* rule)
{
    return PRINTD("%x->%x:%hu/%hu to %x:%hu\n", ntohl(rule->src_addr), 
                  ntohl(rule->dst_addr), ntohs(rule->dst_port), rule->proto, 
                      ntohl(rule->remap_addr), ntohs(rule->remap_port));
}


/* Handle read() calls to REMAP_PROC_FILE.
We don't currently let users read anything through REMAP_PROC_FILE. */
static int 
remap_proc_read(char* buffer, char** buffer_location, off_t offset, 
                int buffer_length, int* eof, void* data)
{
    *eof = 1;
    return 0;
}


/* Handle write() calls to REMAP_PROC_FILE.
Read a struct ipt_remap from userspace and put it in the hash table */
static int 
remap_proc_write(struct file* file, const char* buffer, unsigned long count, 
                 void* data)
{
    struct ipt_remap rule;
    int ret;
    
    /* get the rule from userspace */
    if (count != sizeof(rule))
        return -EINVAL;
    if (copy_from_user(&rule, buffer, sizeof(rule)))
        return -EFAULT;

    /* insert the rule into the hash table */ 
    ret = remap_hash_insert(&rule);
    if (ret)
        return ret;
    
    print_rule(&rule);
    
    return sizeof(rule);
}


/* iptables target function 
Check if there is an applicable remap rule for this packet, and if so, 
remap it. */
static unsigned int
ipt_remap_target(struct sk_buff** pskb,
                 const struct net_device* in,
                 const struct net_device* out,
                 unsigned int hooknum,
                 const struct xt_target* target,
                 const void* target_info)
{
    struct nf_conn* ct;
    enum ip_conntrack_info ctinfo;
    struct iphdr* iph;
    struct tcphdr* tcph;
    struct udphdr* udph;
    struct ipt_remap rule;
    struct nf_nat_range nat_range;
    int ret = NF_ACCEPT;

    NF_CT_ASSERT(hooknum == NF_IP_PRE_ROUTING);
    
    ct = nf_ct_get(*pskb, &ctinfo);
    
    /* make sure that the connection is valid and new */
    NF_CT_ASSERT(ct && ((ctinfo == IP_CT_NEW) || (ctinfo == IP_CT_RELATED)));
    
    iph = (*pskb)->nh.iph;
    rule.src_addr = iph->saddr;
    rule.dst_addr = iph->daddr;
    
    /* only remap supported protocols */
    if ((*pskb)->nh.iph->protocol == IPPROTO_TCP)
    {
        /* check if there is a remap rule corresponding to this packet */
        tcph = (void*)iph + (iph->ihl*4);
        rule.dst_port = tcph->dest;
        rule.proto = IPPROTO_TCP;
        if (!remap_hash_remove(&rule))
        {
            /* build the NAT rule */
            memset(&nat_range, 0, sizeof(nat_range));
            if (rule.remap_port != 0)
            {
                nat_range.flags |= IP_NAT_RANGE_PROTO_SPECIFIED;
                nat_range.min.tcp.port = rule.remap_port;
                nat_range.max.tcp.port = rule.remap_port;
            }
            if (rule.remap_addr != 0)
            {
                nat_range.flags |= IP_NAT_RANGE_MAP_IPS;
                nat_range.min_ip = rule.remap_addr;
                nat_range.max_ip = rule.remap_addr;
            }
            
            /* NAT the packet */
            ret = nf_nat_setup_info(ct, &nat_range, hooknum);

            PRINTD("remapping packet %x->%x:%hu/TCP to %x:%hu\n", 
                   ntohl(iph->saddr), ntohl(iph->daddr), ntohs(tcph->dest), 
                   ntohl(rule.remap_addr), ntohs(rule.remap_port));
        }
    }
    else if ((*pskb)->nh.iph->protocol == IPPROTO_UDP)
    {
        /* check if there is a remap rule corresponding to this packet */
        udph = (void*)iph + (iph->ihl*4);
        rule.dst_port = udph->dest;
        rule.proto = IPPROTO_UDP;
        if (!remap_hash_remove(&rule))
        {
            /* build the NAT rule*/
            memset(&nat_range, 0, sizeof(nat_range));
            if (rule.remap_port != 0)
            {
                nat_range.flags |= IP_NAT_RANGE_PROTO_SPECIFIED;
                nat_range.min.udp.port = rule.remap_port;
                nat_range.max.udp.port = rule.remap_port;
            }
            if (rule.remap_addr != 0)
            {
                nat_range.flags |= IP_NAT_RANGE_MAP_IPS;
                nat_range.min_ip = rule.remap_addr;
                nat_range.max_ip = rule.remap_addr;
            }
            
            /* NAT the packet */
            ret = nf_nat_setup_info(ct, &nat_range, hooknum);

            PRINTD("remapping packet %x->%x:%hu/UDP to %x:%hu\n", 
                   ntohl(iph->saddr), ntohl(iph->daddr), ntohs(udph->dest), 
                   ntohl(rule.remap_addr), ntohs(rule.remap_port));
        }
    }
    else
    {
        PRINTD("received packet: unknown protocol %hu\n", 
               (*pskb)->nh.iph->protocol);
    }
        
    return ret;
}


/* iptables rule validity check 
Make sure that we're running in an appropriate table and chain. */
static int
ipt_remap_checkentry(const char* tablename,
                     const void* e,
                     const struct xt_target* target,
                     void* target_info,
                     unsigned int hook_mask)
{
    /* make sure we're running in PREROUTING chain of the nat table */
    if ((strcmp(tablename, "nat") != 0) 
        || (hook_mask & ~(1 << NF_IP_PRE_ROUTING)))
    {
        printk(KERN_WARNING "ipt_REMAP: may only be called from the "
               "\"PREROUTING\" chain of the \"nat\" table\n");
        return 0;
    }
    
    return 1;
}


/* iptables rule destructor 
We don't store any per-rule data, so there's nothing to do. */
static void
ipt_target_destroy(const struct xt_target* target, void* target_info)
{
    return;
}


/* iptables target handle */
static struct ipt_target remap_target = {
    .list           = {NULL, NULL},
    .name           = "REMAP",
    .target         = ipt_remap_target,
    .checkentry     = ipt_remap_checkentry,
    .destroy        = ipt_target_destroy,
    .me             = THIS_MODULE
};


/* Module constructor
Create REMAP_PROC_FILE, initialize the hash table, and register the iptables
target. */
static int __init 
init(void)
{
    int ret;
    
    /* reate REMAP_PROC_FILE */
    proc_remap = create_proc_entry(REMAP_PROC_FILE, 0200, NULL);
    if (proc_remap == NULL)
    {
        printk(KERN_WARNING "ipt_REMAP: error creating /proc/%s\n", 
               REMAP_PROC_FILE);
        ret = -ENOMEM;
        goto err_create_proc_entry;
    }
    proc_remap->read_proc = remap_proc_read;
    proc_remap->write_proc = remap_proc_write;
    proc_remap->owner = THIS_MODULE;
    
    /* initialize the hash table */
    remap_hash_init();
    
    /* register the target */
    ret = ipt_register_target(&remap_target);
    if (ret != 0)
        goto err_register_target;
    
    return 0;

err_register_target:
    remove_proc_entry(REMAP_PROC_FILE, NULL);
err_create_proc_entry:
    return ret;
}


/* Module destructor
Unregister the iptables target, free the hash table, and remove 
REMAP_PROC_FILE. */
static void __exit 
fini(void)
{
    ipt_unregister_target(&remap_target);
    remap_hash_fini();
    remove_proc_entry(REMAP_PROC_FILE, NULL);
}

module_init(init);
module_exit(fini);
