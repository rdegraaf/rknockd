/* 
 * Iptables userspace module for iptables REMAP target
 * $Id$
 *
 * (C) 2007 Rennie deGraaf <degraaf@cpsc.ucalgary.ca>
 *
 * This program is free software; you may redistribute and/or modify
 * it under the terms of the GNU General Public Licence version 2 as
 * published by the Free Software Foundation.
 */
 
#include <stdio.h>
#include <getopt.h>
#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

static void 
help(void) 
{
    printf("APPL target v%s takes no options.\n", IPTABLES_VERSION); 
}

static void
init(struct ipt_entry_target* t, unsigned int* nfcache)
{}

static int 
parse(int c, char** argv, int invert, unsigned int* flags,
      const struct ipt_entry* entry, struct ipt_entry_target** target)
{
    return 0;
}

static void 
final_check(unsigned int flags)
{}

static void
print(const struct ipt_ip* ip, const struct ipt_entry_target* target, 
      int numeric)
{}

static void
save(const struct ipt_ip* ip, const struct ipt_entry_target* target)
{}

static struct option opts[] = {
    { NULL },
};

static struct iptables_target remap = {
    .next               = NULL,
    .name               = "REMAP",
    .version            = IPTABLES_VERSION,
    .size               = IPT_ALIGN(0),
    .userspacesize      = IPT_ALIGN(0),
    .help               = &help,
    .init               = &init,
    .parse              = &parse,
    .final_check        = &final_check,
    .print              = &print,
    .save               = &save,
    .extra_opts	        = opts
};


void 
_init(void) 
{
    register_target(&remap);
}
