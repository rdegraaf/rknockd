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
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
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

struct remap_hash_entry
{
    struct ipt_remap rule;
    unsigned long expires;
};

/* FIXME: add a timer to clean old entries from the hash table */

#define REMAP_HASH_BITS 7
#define REMAP_HASH_TIMEOUT 5000

static struct remap_hash_entry remap_hash_table[1<<REMAP_HASH_BITS];
static unsigned long remap_hash_collisions = 0;
static unsigned remap_hash_count = 0;
static struct timer_list remap_hash_timer;
static spinlock_t remap_hash_lock = SPIN_LOCK_UNLOCKED;

static struct proc_dir_entry* proc_remap = NULL;

static void
remap_hash_gc(unsigned long data)
{
    unsigned i;
    unsigned long next = jiffies + msecs_to_jiffies(REMAP_HASH_TIMEOUT);
    
    
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

static void 
remap_hash_fini(void)
{
    /* cancel the garbage collector */
    if (timer_pending(&remap_hash_timer))
        del_timer(&remap_hash_timer);
}

static inline unsigned 
remap_hash_fn(const struct ipt_remap* rule)
{
    return hash_long(rule->src_addr, REMAP_HASH_BITS)
         ^ hash_long(rule->dst_addr, REMAP_HASH_BITS)
         ^ hash_long(rule->dst_port, REMAP_HASH_BITS)
         ^ hash_long(rule->proto, REMAP_HASH_BITS);
}

static inline int
remap_hash_compare(const struct ipt_remap* a, const struct ipt_remap* b)
{
    if ((b->src_addr == a->src_addr) && (b->dst_addr == a->dst_addr)
        && (b->dst_port == a->dst_port) && (b->proto == a->proto))
        return 1;
    else
        return 0;
}


static int 
remap_hash_insert(const struct ipt_remap* rule)
{
    unsigned hash;
    
    /* make sure that the rule is valid */
    if ((rule->src_addr == 0) || (rule->dst_addr == 0) || (rule->dst_port == 0))
        return -EINVAL;
    
    hash = remap_hash_fn(rule);

    spin_lock_bh(&remap_hash_lock);
    
    /* check for overflow */
    if (remap_hash_count == (1<<REMAP_HASH_BITS))
    {
        printk(KERN_WARNING "ipt_REMAP: hash table full; dropping rule\n");
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
    remap_hash_table[hash].expires = jiffies 
                                     + msecs_to_jiffies(REMAP_HASH_TIMEOUT);
    remap_hash_count++;
    
    /* schedule the garbage collector */
    /* if this is the only entry, then the gc is already scheduled */
    if (remap_hash_count == 1)
    {
        remap_hash_timer.expires = jiffies 
                                   + msecs_to_jiffies(REMAP_HASH_TIMEOUT);
        add_timer(&remap_hash_timer);
    }

    spin_unlock_bh(&remap_hash_lock);

    return 0;
}

static int
remap_hash_remove(struct ipt_remap* rule)
{
    unsigned hash;
    int count = 0;
    
    hash = remap_hash_fn(rule);
    
    spin_lock_bh(&remap_hash_lock);

    /* check for underflow */
    if (remap_hash_count == 0)
        return -ENOENT;

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

static inline int 
print_rule(const struct ipt_remap* rule)
{
    return PRINTD("%x->%x:%hu/%hu to %x:%hu\n", rule->src_addr, 
                  rule->dst_addr, rule->dst_port, rule->proto, 
                  rule->remap_addr, rule->remap_port);
}

    
static int 
read(char* buffer, char** buffer_location, off_t offset, int buffer_length,
     int* eof, void* data)
{
    *eof = 1;
    return 0;
}

int write(struct file* file, const char* buffer, unsigned long count, 
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
    
    /*if (!remap_hash_insert(&rule))
        printk(KERN_WARNING "ipt_REMAP: error detecting duplicate entry\n");
    if (remap_hash_remove(&rule))
        printk(KERN_WARNING "ipt_REMAP: error looking up entry\n");
    if (!remap_hash_remove(&rule))
        printk(KERN_WARNING "ipt_REMAP: error deleting entry\n");*/
    
    return sizeof(rule);
}



static unsigned int
target(struct sk_buff** pskb,
       const struct net_device* in,
       const struct net_device* out,
       unsigned int hooknum,
       const void* target_info,
       void* userinfo)
{
    struct ip_conntrack* ct;
    enum ip_conntrack_info ctinfo;

    IP_NF_ASSERT(hooknum == NF_IP_PRE_ROUTING);
    
    ct = ip_conntrack_get(*pskb, &ctinfo);
    
    /* make sure that the connection is valid and new */
    IP_NF_ASSERT(ct && ((ctinfo == IP_CT_NEW) || (ctinfo == IP_CT_RELATED)));
    
    
    if ((*pskb)->nh.iph->protocol == htons(IPPROTO_TCP))
    {
        PRINTD("received packet: %x->%x:%hu/%hu\n", (*pskb)->nh.iph->saddr, 
               (*pskb)->nh.iph->daddr, (*pskb)->h.th->dest, 
               (*pskb)->nh.iph->protocol);
    }
    else if ((*pskb)->nh.iph->protocol == htons(IPPROTO_UDP))
    {
        PRINTD("received packet: %x->%x:%hu/%hu\n", 
               (*pskb)->nh.iph->saddr, 
               (*pskb)->nh.iph->daddr, (*pskb)->h.uh->dest, 
               (*pskb)->nh.iph->protocol);
    }
    else
        PRINTD("received packet: unknown protocol %hu\n", 
               (*pskb)->nh.iph->protocol);
    
    return NF_ACCEPT;
}

static int
check(const char* tablename,
      const void* e,
      void* target_info,
      unsigned int target_info_size,
      unsigned int hook_mask)
{
    /* check size of target_into */
    if (target_info_size != 0)
    {
        printk(KERN_WARNING "ipt_REMAP: target_into_size %u != 0\n", 
               target_info_size);
        return 0;
    }
    
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

static void
destroy(void* target_info, unsigned int target_info_size)
{
    return;
}



static struct ipt_target remap_target = {
    .list           = {NULL, NULL},
    .name           = "REMAP",
    .target         = target,
    .checkentry     = check,
    .destroy        = destroy,
    .me             = THIS_MODULE
};

static int __init init(void)
{
    int ret;
    
    proc_remap = create_proc_entry(REMAP_PROC_FILE, 0200, NULL);
    if (proc_remap == NULL)
    {
        printk(KERN_WARNING "ipt_REMAP: error creating /proc/%s\n", 
               REMAP_PROC_FILE);
        ret = -ENOMEM;
        goto err_create_proc_entry;
    }
    proc_remap->read_proc = read;
    proc_remap->write_proc = write;
    proc_remap->owner = THIS_MODULE;
    
    /* register the target */
    ret = ipt_register_target(&remap_target);
    if (ret != 0)
        goto err_register_target;
    
    remap_hash_init();
    
    return 0;

err_register_target:
    remove_proc_entry(REMAP_PROC_FILE, NULL);
err_create_proc_entry:
    return ret;
}

static void __exit fini(void)
{
    remap_hash_fini();
    ipt_unregister_target(&remap_target);
    remove_proc_entry(REMAP_PROC_FILE, NULL);
}

module_init(init);
module_exit(fini);
