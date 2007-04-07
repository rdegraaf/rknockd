/* 
 * Iptables userspace module for REMAP target
 * $Id: libipt_appl.c 22 2006-11-07 00:35:45Z degraaf $
 *
 * Copyright Rennie deGraaf 2007 <degraaf@cpsc.ucalgary.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
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
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry, unsigned int *nfcache,
      struct ipt_entry_match **match)
{
    return 0;
}

static void 
final_check(unsigned int flags)
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
    .print              = NULL,
    .save               = NULL,
    .extra_opts	        = opts
};


void 
_init(void) 
{
    register_match(&remap);
}
