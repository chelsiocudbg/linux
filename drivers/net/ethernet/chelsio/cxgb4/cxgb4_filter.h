/*
 * This file is part of the Chelsio T4 Ethernet driver for Linux.
 *
 * Copyright (c) 2003-2016 Chelsio Communications, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __CXGB4_FILTER_H
#define __CXGB4_FILTER_H

#include "t4_msg.h"
#define CXGB4_FILTER_ID_ANY UINT_MAX

/* Defined bit width of user definable filter tuples
 */
#define ETHTYPE_BITWIDTH 16
#define FRAG_BITWIDTH 1
#define MACIDX_BITWIDTH 9
#define FCOE_BITWIDTH 1
#define IPORT_BITWIDTH 3
#define MATCHTYPE_BITWIDTH 3
#define PROTO_BITWIDTH 8
#define TOS_BITWIDTH 8
#define PF_BITWIDTH 8
#define VF_BITWIDTH 8
#define IVLAN_BITWIDTH 16
#define OVLAN_BITWIDTH 16
#define ENCAP_VNI_BITWIDTH 24
#define IPSECIDX_BITWIDTH 12
#define ROCE_BITWIDTH 1
#define SYNONLY_BITWIDTH 1
#define TCPFLAGS_BITWIDTH 12

/* Filter matching rules.  These consist of a set of ingress packet field
 * (value, mask) tuples.  The associated ingress packet field matches the
 * tuple when ((field & mask) == value).  (Thus a wildcard "don't care" field
 * rule can be constructed by specifying a tuple of (0, 0).)  A filter rule
 * matches an ingress packet when all of the individual field
 * matching rules are true.
 *
 * Partial field masks are always valid, however, while it may be easy to
 * understand their meanings for some fields (e.g. IP address to match a
 * subnet), for others making sensible partial masks is less intuitive (e.g.
 * MPS match type) ...
 *
 * Most of the following data structures are modeled on T4 capabilities.
 * Drivers for earlier chips use the subsets which make sense for those chips.
 * We really need to come up with a hardware-independent mechanism to
 * represent hardware filter capabilities ...
 */
struct ch_filter_tuple {
	/* Compressed header matching field rules.  The TP_VLAN_PRI_MAP
	 * register selects which of these fields will participate in the
	 * filter match rules -- up to a maximum of 36 bits.  Because
	 * TP_VLAN_PRI_MAP is a global register, all filters must use the same
	 * set of fields.
	 */
	uint32_t ethtype:ETHTYPE_BITWIDTH;      /* Ethernet type */
	uint32_t frag:FRAG_BITWIDTH;            /* IP fragmentation header */
	uint32_t ivlan_vld:1;                   /* inner VLAN valid */
	uint32_t ovlan_vld:1;                   /* outer VLAN valid */
	uint32_t pfvf_vld:1;                    /* PF/VF valid */
	uint32_t encap_vld:1;			/* Encapsulation valid */
	uint32_t macidx:MACIDX_BITWIDTH;        /* exact match MAC index */
	uint32_t fcoe:FCOE_BITWIDTH;            /* FCoE packet */
	uint32_t iport:IPORT_BITWIDTH;          /* ingress port */
	uint32_t matchtype:MATCHTYPE_BITWIDTH;  /* MPS match type */
	uint32_t proto:PROTO_BITWIDTH;          /* protocol type */
	uint32_t tos:TOS_BITWIDTH;              /* TOS/Traffic Type */
	uint32_t pf:PF_BITWIDTH;                /* PCI-E PF ID */
	uint32_t vf:VF_BITWIDTH;                /* PCI-E VF ID */
	uint32_t ivlan:IVLAN_BITWIDTH;          /* inner VLAN */
	uint32_t ovlan:OVLAN_BITWIDTH;          /* outer VLAN */
	uint32_t vni:ENCAP_VNI_BITWIDTH;	/* VNI of tunnel */
	uint32_t ipsecidx:IPSECIDX_BITWIDTH;    /* IPSec Index */
	uint32_t roce:ROCE_BITWIDTH;            /* RoCE packet match */
	uint32_t synonly:SYNONLY_BITWIDTH;      /* SYN packet match only */
	uint32_t tcpflags:TCPFLAGS_BITWIDTH;    /* TCP flags */

	/* Uncompressed header matching field rules.  These are always
	 * available for field rules.
	 */
	uint8_t lip[16];        /* local IP address (IPv4 in [3:0]) */
	uint8_t fip[16];        /* foreign IP address (IPv4 in [3:0]) */
	uint16_t lport;         /* local port */
	uint16_t fport;         /* foreign port */

	uint32_t rocev2_qpn;    /* RoCEv2 QPN for GSI filter */

};

/* A filter ioctl command.
 */
struct ch_filter_specification {
	/* Administrative fields for filter.
	 */
	uint32_t hitcnts:1;     /* count filter hits in TCB */
	uint32_t prio:1;        /* filter has priority over active/server */

	/* Fundamental filter typing.  This is the one element of filter
	 * matching that doesn't exist as a (value, mask) tuple.
	 */
	uint32_t type:1;        /* 0 => IPv4, 1 => IPv6 */
	u32 hash:1;		/* 0 => wild-card, 1 => exact-match */

	/* Packet dispatch information.  Ingress packets which match the
	 * filter rules will be dropped, passed to the host or switched back
	 * out as egress packets.
	 */
	uint32_t action:2;      /* drop, pass, switch */

	uint32_t rpttid:1;      /* report TID in RSS hash field */

	uint32_t dirsteer:1;    /* 0 => RSS, 1 => steer to iq */
	uint32_t iq:10;         /* ingress queue */

	uint32_t maskhash:1;    /* dirsteer=0: store RSS hash in TCB */
	uint32_t dirsteerhash:1;/* dirsteer=1: 0 => TCB contains RSS hash */
				/*             1 => TCB contains IQ ID */

	/* Switch proxy/rewrite fields.  An ingress packet which matches a
	 * filter with "switch" set will be looped back out as an egress
	 * packet -- potentially with some Ethernet header rewriting.
	 */
	uint32_t eport:2;       /* egress port to switch packet out */
	uint32_t newdmac:1;     /* rewrite destination MAC address */
	uint32_t newsmac:1;     /* rewrite source MAC address */
	uint32_t swapmac:1;     /* swap SMAC/DMAC for loopback packet */
	uint32_t newvlan:2;     /* rewrite VLAN Tag */
	uint32_t nat_mode:3;    /* specify NAT operation mode */
	uint8_t dmac[ETH_ALEN]; /* new destination MAC address */
	uint8_t smac[ETH_ALEN]; /* new source MAC address */
	uint16_t vlan;          /* VLAN Tag to insert */

	u8 nat_lip[16];		/* local IP to use after NAT'ing */
	u8 nat_fip[16];		/* foreign IP to use after NAT'ing */
	u16 nat_lport;		/* local port to use after NAT'ing */
	u16 nat_fport;		/* foreign port to use after NAT'ing */

	u32 tc_prio;		/* TC's filter priority index */
	u64 tc_cookie;		/* Unique cookie identifying TC rules */

	/* reservation for future additions */
	u8 rsvd[12];

	/* Filter rule value/mask pairs.
	 */
	struct ch_filter_tuple val;
	struct ch_filter_tuple mask;
};

struct filter_ehash_bucket {
       struct hlist_nulls_head chain;
};

struct filter_hashinfo {
       struct filter_ehash_bucket *ehash;
       spinlock_t *ehash_filter_locks; /* Lock to access ehash table */
       unsigned int ehash_mask;
       unsigned int ehash_filter_locks_mask;
};

/* Filter operation context to allow callers of cxgb_set_filter() and
 * cxgb_del_filter() to wait for an asynchronous completion.
 */
struct filter_ctx {
       struct completion completion;   /* completion rendezvous */
       void *closure;                  /* caller's opaque information */
       int result;                     /* result of operation */
       u32 tid;                        /* to store tid of hash filter */
};

/* Host shadow copy of ingress filter entry.  This is in host native format
 * and doesn't match the ordering or bit order, etc. of the hardware or the
 * firmware command.
 */
struct filter_entry {
       /*
        * Administrative fields for filter.
        */
       u32 valid:1;            /* filter allocated and valid */
       u32 locked:1;           /* filter is administratively locked */
       u32 pending:1;          /* filter action is pending firmware reply */
       u32 smtidx:8;           /* Source MAC Table index for smac */
       struct filter_ctx *ctx; /* caller's completion hook */
       struct l2t_entry *l2t;  /* Layer Two Table entry for dmac */
       struct smt_entry *smt;  /* Source Mac Table entry for smac */
       struct net_device *dev;
       /* This will store the actual tid */
       u32 tid;
       unsigned int filter_hash;
       struct hlist_nulls_node filter_nulls_node;
       u64 pkt_counter;
       u64 byte_counter;

       /*
        * The filter itself.  Most of this is a straight copy of information
        * provided by the extended ioctl().  Some fields are translated to
        * internal forms -- for instance the Ingress Queue ID passed in from
        * the ioctl() is translated into the Absolute Ingress Queue ID.
        */
       struct ch_filter_specification fs;
};

#define WORD_MASK	0xffffffff

struct cpl_set_tcb_rpl;
struct cpl_act_open_rpl;
struct cpl_abort_rpl_rss;

void filter_rpl(struct adapter *adap, const struct cpl_set_tcb_rpl *rpl);
void hash_filter_rpl(struct adapter *adap, const struct cpl_act_open_rpl *rpl);
void hash_del_filter_rpl(struct adapter *adap,
                        const struct cpl_abort_rpl_rss *rpl);
void clear_filter(struct adapter *adap, struct filter_entry *f);

int set_filter_wr(struct adapter *adapter, int fidx);
int delete_filter(struct adapter *adapter, unsigned int fidx);

int writable_filter(struct filter_entry *f);
void clear_all_filters(struct adapter *adapter);
void init_hash_filter(struct adapter *adap);
bool is_filter_exact_match(struct adapter *adap,
                           struct ch_filter_specification *fs);
void cxgb4_cleanup_ethtool_filters(struct adapter *adap);
int cxgb4_init_ethtool_filters(struct adapter *adap);


int cxgb4_create_server_filter(const struct net_device *dev, unsigned int stid,
                              __be32 sip, __be16 sport, __be16 vlan,
                              unsigned int queue,
                              unsigned char port, unsigned char mask);
int cxgb4_remove_server_filter(const struct net_device *dev, unsigned int stid,
                              unsigned int queue, bool ipv6);

int __cxgb4_set_filter(struct net_device *dev, int filter_id,
                      struct ch_filter_specification *fs,
                      struct filter_ctx *ctx);
int __cxgb4_del_filter(struct net_device *dev, int filter_id,
                      struct ch_filter_specification *fs,
                      struct filter_ctx *ctx);
int cxgb4_set_filter(struct net_device *dev, int filter_id,
                    struct ch_filter_specification *fs);
int cxgb4_del_filter(struct net_device *dev, int filter_id,
                    struct ch_filter_specification *fs);
int cxgb4_get_filter_counters(struct net_device *dev, unsigned int fidx,
                             u64 *hitcnt, u64 *bytecnt, bool hash);
#endif /* __CXGB4_FILTER_H */
