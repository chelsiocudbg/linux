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
#include <net/ipv6.h>

#include "cxgb4.h"
#include "t4_regs.h"
#include "t4_tcb.h"
#include "t4_values.h"
#include "clip_tbl.h"
#include "l2t.h"
#include "smt.h"
#include "t4fw_api.h"
#include "cxgb4_filter.h"
#include "cxgb4_debugfs.h"

/* Validate filter spec against configuration done on the card. */
static int cxgb4_filter_validate(struct net_device *dev,
				 struct ch_filter_specification *fs)
{
	struct adapter *adapter = netdev2adap(dev);
	u32 fconf, f_mask, iconf, chip_ver;
	bool unsupp;

	/* Check for unconfigured fields being used. */
	fconf = adapter->params.tp.vlan_pri_map;
	f_mask = adapter->params.tp.filter_mask;
	iconf = adapter->params.tp.ingress_config;
	chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);

#define S(_field) (fs->val._field || fs->mask._field)

	/* If cap is maskless then validate filter_mask else filter_mode */
#define U(_mask, _field) (!((fs->hash ? f_mask : fconf) & (_mask)) && S(_field))

	if (chip_ver >= CHELSIO_T7)
		unsupp = U(IPSECIDX_F, ipsecidx) || U(T7_FCOE_F, fcoe) ||
			 U(T7_PORT_F, iport) || U(T7_TOS_F, tos) ||
			 U(T7_ETHERTYPE_F, ethtype) ||
			 U(T7_MACMATCH_F, macidx) ||
			 U(T7_MPSHITTYPE_F, matchtype) ||
			 U(T7_FRAGMENTATION_F, frag) ||
			 U(T7_PROTOCOL_F, proto) ||
			 U(T7_VNIC_ID_F, pfvf_vld) ||
			 U(T7_VNIC_ID_F, ovlan_vld) ||
			 U(T7_VNIC_ID_F, encap_vld) ||
			 U(T7_VLAN_F, ivlan_vld) ||
			 U(ROCE_F, roce) || U(SYNONLY_F, synonly) ||
			 U(TCPFLAGS_F, tcpflags);
	else
		unsupp = U(FCOE_F, fcoe) || U(PORT_F, iport) ||
			 U(TOS_F, tos) || U(ETHERTYPE_F, ethtype) ||
			 U(MACMATCH_F, macidx) ||
			 U(MPSHITTYPE_F, matchtype) ||
			 U(FRAGMENTATION_F, frag) ||
			 U(PROTOCOL_F, proto) ||
			 U(VNIC_ID_F, pfvf_vld) ||
			 U(VNIC_ID_F, ovlan_vld) ||
			 U(VNIC_ID_F, encap_vld) ||
			 U(VLAN_F, ivlan_vld);

	if (unsupp)
		return -EOPNOTSUPP;

	/* T4 inconveniently uses the same FT_VNIC_ID_W bits for both the Outer
	 * VLAN Tag and PF/VF/VFvld fields based on VNIC_F being set
	 * in TP_INGRESS_CONFIG.  Hense the somewhat crazy checks
	 * below.  Additionally, since the T4 firmware interface also
	 * carries that overlap, we need to translate any PF/VF
	 * specification into that internal format below.
	 */
	if ((S(pfvf_vld) && S(ovlan_vld)) ||
	    (S(pfvf_vld) && S(encap_vld)) ||
	    (S(ovlan_vld) && S(encap_vld)))
		return -EOPNOTSUPP;
	if ((S(pfvf_vld) && !(iconf & VNIC_F)) ||
	    (S(ovlan_vld) && (iconf & VNIC_F)))
		return -EOPNOTSUPP;
	if (chip_ver <= CHELSIO_T6 &&
	    (S(ipsecidx) || S(roce) || S(synonly) || S(tcpflags)))
		return -EOPNOTSUPP;

	if (fs->val.pf > 0x7 || fs->val.vf > 0x7f)
		return -ERANGE;
	fs->mask.pf &= 0x7;
	fs->mask.vf &= 0x7f;

	#undef S
	#undef U

	if (fs->val.encap_vld && chip_ver < CHELSIO_T6)
		return -EOPNOTSUPP;

	/*
	 * Don't allow various trivially obvious bogus out-of-range
	 * values ...
	 */
	if (fs->val.iport >= adapter->params.nports)
		return -ERANGE;

	/*
	 * If the user is requesting that the filter action loop
	 * matching packets back out one of our ports, make sure that
	 * the egress port is in range.
	 */
	if (fs->action == FILTER_SWITCH &&
	    fs->eport >= adapter->params.nports) {
	    	/* in t6, loopback channel is supported, which starts from 4
 		 * (NUM_UP_TSCH_CHANNEL_INSTANCES), in that case egress
	    	 * port can be 0-1 or 4-5.
	    	 */
		if (chip_ver > CHELSIO_T5) {
			if ((fs->eport >= adapter->params.nports &&
			     fs->eport < NUM_UP_TSCH_CHANNEL_INSTANCES) ||
			    (fs->eport >= (adapter->params.nports +
					   NUM_UP_TSCH_CHANNEL_INSTANCES)))
				return -ERANGE;
		} else {
			return -ERANGE;
		}
	}

	/*
	 * T4 doesn't support removing VLAN Tags for loop back
	 * filters. Also, swapmac and NAT are not supported on T4.
	 */
	if (is_t4(adapter->params.chip) &&
	    fs->action == FILTER_SWITCH &&
	    (fs->newvlan == VLAN_REMOVE ||
	     fs->newvlan == VLAN_REWRITE))
		return -EOPNOTSUPP;

	if (is_t4(adapter->params.chip) &&
	    fs->action == FILTER_SWITCH &&
	    fs->swapmac)
		return -EOPNOTSUPP;

	if (is_t4(adapter->params.chip) &&
	    fs->action == FILTER_SWITCH &&
	    fs->nat_mode)
		return -EOPNOTSUPP;

	return 0;
}

static u8 cxgb4_hash_filter_get_tx_chan(struct adapter *adap,
                                        struct filter_entry *f)
{
        if (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T6)
                return f->fs.eport & (NUM_UP_TSCH_CHANNEL_INSTANCES - 1);

	return 0;
}

static u8 cxgb4_hash_filter_get_rx_chan(struct adapter *adap,
                                        struct filter_entry *f)
{
        if (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T6)
                return cxgb4_port_e2cchan(f->dev);

        /* For T7, the Tx and Rx Channel are a single opaque field
         * called just the "Channel". Hence, the legacy Rx channel
         * field is deprecated and needs to be filled with 0.
         */
        return 0;
}

static int cxgb4_filter_get_steerq(struct net_device *dev,
                                   struct ch_filter_specification *fs)
{
        struct adapter *adapter = netdev2adap(dev);
        struct port_info *pi = netdev_priv(dev);

        /* If the user has requested steering matching Ingress Packets
         * to a specific Queue Set, we need to make sure it's in range
         * for the port and map that into the Absolute Queue ID of the
         * Queue Set's Response Queue.
         */
        if (!fs->dirsteer) {
                if (fs->iq)
                        return -EINVAL;

                return 0;
        }

        /* If the iq id is greater than the number of qsets, then assume
         * it is an absolute qid.
         */
        if (fs->iq < pi->nqsets)
                return adapter->sge.ethrxq[pi->first_qset + fs->iq].rspq.abs_id;

        return fs->iq;
}

static void cxgb4_filter_hw_resources_free(struct adapter *adap,
                                           struct filter_entry *f)
{
        struct port_info *pi = netdev_priv(f->dev);

        /* If the filter has loopback rewriting rules then we'll need to free
         * any existing Layer Two Table (L2T) entries of the filter rule.  The
         * firmware will handle freeing up any Source MAC Table (SMT) entries
         * used for rewriting Source MAC Addresses in loopback rules.
         */
        if (f->l2t) {
                cxgb4_l2t_release(f->l2t);
                f->l2t = NULL;
        }

        if (f->smt) {
                cxgb4_smt_release(f->smt);
                f->smt = NULL;
        }

        if (f->fs.val.encap_vld && f->fs.val.ovlan_vld) {
                cxgb4_free_encap_mac_filt(adap, pi->viid,
                                         f->fs.val.ovlan & 0x1ff, 0);
                f->fs.val.encap_vld = 0;
                f->fs.val.ovlan_vld = 0;
        }

        if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T6 && f->fs.type)
		cxgb4_clip_release(f->dev, (const u32 *)&f->fs.val.lip, 1);
}

static int cxgb4_filter_match_parse(struct adapter *adap,
                                    struct filter_entry *f)
{
        u32 iconf;
        int ret;

        iconf = adap->params.tp.ingress_config;
        if (iconf & VNIC_F) {
                f->fs.val.ovlan = (f->fs.val.pf << 13) | f->fs.val.vf;
                f->fs.mask.ovlan = (f->fs.mask.pf << 13) | f->fs.mask.vf;
                f->fs.val.ovlan_vld = f->fs.val.pfvf_vld;
                f->fs.mask.ovlan_vld = f->fs.mask.pfvf_vld;
        } else if ((iconf & USE_ENC_IDX_F) && f->fs.val.encap_vld) {
                struct port_info *pi = netdev_priv(f->dev);

                /* Allocate MPS TCAM entry for encapsulation MAC match */
                ret = cxgb4_alloc_encap_mac_filt(adap, pi->viid,
                                                0,// f->fs.val.encap_inner_mac,
                                                0,//f->fs.mask.encap_inner_mac,
                                                f->fs.val.vni,
                                                f->fs.mask.vni, 0,
                                                0,//f->fs.val.encap_lookup,
						1);
                if (ret < 0)
                        goto out_err;

                f->fs.val.ovlan = 0;
                f->fs.mask.ovlan = 0;
                f->fs.val.ovlan_vld = 1;
                f->fs.mask.ovlan_vld = 1;
        }

        /* Issue a cxgb4_clip_get() only if we have non-zero IPv6
         * address
         */
        if (ipv6_addr_type((const struct in6_addr *)f->fs.val.lip) !=
            IPV6_ADDR_ANY && f->fs.type) {
                ret = cxgb4_clip_get(f->dev, (const u32 *)&f->fs.val.lip, 1);
                if (ret)
                        goto out_err;
        }

        return 0;

out_err:
        cxgb4_filter_hw_resources_free(adap, f);
        return ret;
}

static int cxgb4_filter_action_parse(struct adapter *adap,
                                     struct filter_entry *f)
{
        int ret;

        /* If the new filter requires loopback Destination MAC and/or VLAN
         * rewriting then we need to allocate a Layer 2 Table (L2T) entry for
         * the filter.
         */
        if (f->fs.newdmac || f->fs.newvlan == VLAN_INSERT ||
            f->fs.newvlan == VLAN_REWRITE) {
                /* Allocate L2T entry for new filter */
                f->l2t = t4_l2t_alloc_switching(adap, f->fs.vlan, f->fs.eport,
                                                f->fs.dmac);
                if (!f->l2t) {
                        ret = -ENOMEM;
                        goto out_free;
                }
        }

        /* If the new filter requires loopback Source MAC rewriting then
         * we need to allocate a SMT entry for the filter.
         */
        if (f->fs.newsmac) {
                f->smt = cxgb4_smt_alloc_switching(f->dev, f->fs.smac);
                if (!f->smt) {
                        ret = -ENOMEM;
                        goto out_free;
                }
                f->smtidx = f->smt->hw_idx;
        }

        return 0;

out_free:
        cxgb4_filter_hw_resources_free(adap, f);
        return ret;
}

/* Clear a filter and release any of its resources that we own.  This also
 * clears the filter's "pending" status.
 */
static void cxgb4_filter_clear(struct adapter *adap, struct filter_entry *f)
{
        cxgb4_filter_hw_resources_free(adap, f);

	/* The zeroing of the filter rule below clears the filter valid,
	 * pending, locked flags, l2t pointer, etc. so it's all we need for
	 * this operation.
	 */
	memset(f, 0, sizeof(*f));
}

static void cxgb4_hashtid_filter_clear(struct adapter *adap,
                                       struct filter_entry *f)
{
        spinlock_t *lock = 0; /*Lock for accessing ehash table */

	cxgb4_remove_tid(&adap->tids, 0, f->tid, f->fs.type);

        spin_lock_bh(lock);
        f->valid = 0;
        /* Remove hash entry */
//        hlist_nulls_del_init_rcu(&f->filter_nulls_node);
        spin_unlock_bh(lock);

        cxgb4_filter_clear(adap, f);
	kfree(f);
}

static void cxgb4_ftid_filter_clear(struct adapter *adap,
                                    struct filter_entry *f)
{
        cxgb4_filter_clear(adap, f);
}

/* Return an error number if the indicated filter isn't writable ...
 */
static int cxgb4_filter_writable(struct filter_entry *f)
{
        if (f->locked)
                return -EPERM;
        if (f->pending)
                return -EBUSY;

        return 0;
}

static int cxgb4_set_ftid(struct tid_info *t, int fidx, int family,
			  unsigned int chip_ver)
{
	spin_lock_bh(&t->ftid_lock);

	if (test_bit(fidx, t->ftid_bmap)) {
		spin_unlock_bh(&t->ftid_lock);
		return -EBUSY;
	}

	if (family == PF_INET)
		__set_bit(fidx, t->ftid_bmap);
	else {
		if (chip_ver < CHELSIO_T6)
			bitmap_allocate_region(t->ftid_bmap, fidx, 2);
		else
			bitmap_allocate_region(t->ftid_bmap, fidx, 1);
	}

	spin_unlock_bh(&t->ftid_lock);
	return 0;
}

static int cxgb4_set_hpftid(struct tid_info *t, int fidx, int family,
			    unsigned int chip_ver)
{
	spin_lock_bh(&t->ftid_lock);

	if (test_bit(fidx, t->hpftid_bmap)) {
		spin_unlock_bh(&t->ftid_lock);
		return -EBUSY;
	}

	if (family == PF_INET)
		__set_bit(fidx, t->hpftid_bmap);
	else {
		if (chip_ver < CHELSIO_T6)
			bitmap_allocate_region(t->hpftid_bmap, fidx, 2);
		else
			bitmap_allocate_region(t->hpftid_bmap, fidx, 1);
	}

	spin_unlock_bh(&t->ftid_lock);
	return 0;
}

static void cxgb4_clear_ftid(struct tid_info *t, int fidx, int family,
			     unsigned int chip_ver)
{
	spin_lock_bh(&t->ftid_lock);
	if (family == PF_INET)
		__clear_bit(fidx, t->ftid_bmap);
	else {
		if (chip_ver < CHELSIO_T6)
			bitmap_release_region(t->ftid_bmap, fidx, 2);
		else
			bitmap_release_region(t->ftid_bmap, fidx, 1);
	}
	spin_unlock_bh(&t->ftid_lock);
}

static void cxgb4_clear_hpftid(struct tid_info *t, int fidx, int family,
			       unsigned int chip_ver)
{
	spin_lock_bh(&t->ftid_lock);
	if (family == PF_INET)
		__clear_bit(fidx, t->hpftid_bmap);
	else {
		if (chip_ver < CHELSIO_T6)
			bitmap_release_region(t->hpftid_bmap, fidx, 2);
		else
			bitmap_release_region(t->hpftid_bmap, fidx, 1);
	}
	spin_unlock_bh(&t->ftid_lock);
}

/* Normal Filters
 */

/* Send a Work Request to write the filter at a specified index.  We construct
 * a Firmware Filter Work Request to have the work done and put the indicated
 * filter into "pending" mode which will prevent any further actions against
 * it till we get a reply from the firmware on the completion status of the
 * request.
 */
static int cxgb4_filter_normal_create_wr(struct adapter *adapter, u32 fidx,
					 gfp_t gfp_mask)
{
	struct filter_entry *f = &adapter->tids.ftid_tab[fidx];
	struct fw_filter2_wr *fwr;
        struct sk_buff *skb;
        u32 chip_ver;

        if (gfp_mask & GFP_ATOMIC) {
                skb = alloc_skb(sizeof(*fwr), GFP_ATOMIC);
                if (!skb)
                        return -ENOMEM;
        } else {
                skb = alloc_skb(sizeof(*fwr), gfp_mask | __GFP_NOFAIL);
        }

        fwr = (struct fw_filter2_wr *)__skb_put(skb, sizeof(*fwr));
        memset(fwr, 0, sizeof(*fwr));

        chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);

        /* It would be nice to put most of the following in t4_hw.c but most
         * of the work is translating the cxgbtool ch_filter_specification
         * into the Work Request and the definition of that structure is
         * currently in cxgbtool.h which isn't appropriate to pull into the
         * common code.  We may eventually try to come up with a more neutral
         * filter specification structure but for now it's easiest to simply
         * put this fairly direct code in line ...
         */
        if (adapter->params.filter2_wr_support)
                fwr->op_pkd = htonl(FW_WR_OP_V(FW_FILTER2_WR));
        else
                fwr->op_pkd = htonl(FW_WR_OP_V(FW_FILTER_WR));
        fwr->len16_pkd = htonl(FW_WR_LEN16_V(sizeof(*fwr) / 16));
        fwr->tid_to_iq =
                htonl(FW_FILTER_WR_TID_V(f->tid) |
                      FW_FILTER_WR_RQTYPE_V(f->fs.type) |
                      FW_FILTER_WR_NOREPLY_V(0) |
                      FW_FILTER_WR_IQ_V(f->fs.iq));
        fwr->del_filter_to_l2tix =
                htonl(FW_FILTER_WR_RPTTID_V(f->fs.rpttid) |
                      FW_FILTER_WR_DROP_V(f->fs.action == FILTER_DROP) |
                      FW_FILTER_WR_DIRSTEER_V(f->fs.dirsteer) |
                      FW_FILTER_WR_MASKHASH_V(f->fs.maskhash) |
                      FW_FILTER_WR_DIRSTEERHASH_V(f->fs.dirsteerhash) |
                      FW_FILTER_WR_LPBK_V(f->fs.action == FILTER_SWITCH) |
                      FW_FILTER2_WR_TX_LOOP_V(f->fs.eport >=
                                         NUM_UP_TSCH_CHANNEL_INSTANCES) |
                      FW_FILTER_WR_DMAC_V(f->fs.newdmac) |
                      FW_FILTER_WR_SMAC_V(f->fs.newsmac) |
                      FW_FILTER_WR_INSVLAN_V(f->fs.newvlan == VLAN_INSERT ||
                                             f->fs.newvlan == VLAN_REWRITE) |
                      FW_FILTER_WR_RMVLAN_V(f->fs.newvlan == VLAN_REMOVE ||
                                            f->fs.newvlan == VLAN_REWRITE) |
                      FW_FILTER_WR_HITCNTS_V(f->fs.hitcnts) |
                      FW_FILTER_WR_TXCHAN_V(f->fs.eport &
                                        (NUM_UP_TSCH_CHANNEL_INSTANCES - 1)) |
                      FW_FILTER_WR_PRIO_V(f->fs.prio) |
                      FW_FILTER_WR_L2TIX_V(f->l2t ? f->l2t->idx : 0));
        fwr->ethtype = htons(f->fs.val.ethtype);
        fwr->ethtypem = htons(f->fs.mask.ethtype);
        fwr->frag_to_ovlan_vldm =
                     (FW_FILTER_WR_FRAG_V(f->fs.val.frag) |
                      FW_FILTER_WR_FRAGM_V(f->fs.mask.frag) |
                      FW_FILTER_WR_IVLAN_VLD_V(f->fs.val.ivlan_vld) |
                      FW_FILTER_WR_OVLAN_VLD_V(f->fs.val.ovlan_vld) |
                      FW_FILTER_WR_IVLAN_VLDM_V(f->fs.mask.ivlan_vld) |
                      FW_FILTER_WR_OVLAN_VLDM_V(f->fs.mask.ovlan_vld));
        fwr->smac_sel = f->smtidx;
        fwr->rx_chan_rx_rpl_iq =
                htons(FW_FILTER_WR_RX_RPL_IQ_V(adapter->sge.fw_evtq.abs_id));
        if (chip_ver <= CHELSIO_T6)
                fwr->rx_chan_rx_rpl_iq |=
                        htons(FW_FILTER_WR_RX_CHAN_V(cxgb4_port_e2cchan(f->dev)));
        fwr->maci_to_matchtypem =
                htonl(FW_FILTER_WR_MACI_V(f->fs.val.macidx) |
                      FW_FILTER_WR_MACIM_V(f->fs.mask.macidx) |
                      FW_FILTER_WR_FCOE_V(f->fs.val.fcoe) |
                      FW_FILTER_WR_FCOEM_V(f->fs.mask.fcoe) |
                      FW_FILTER_WR_PORT_V(f->fs.val.iport) |
                      FW_FILTER_WR_PORTM_V(f->fs.mask.iport) |
                      FW_FILTER_WR_MATCHTYPE_V(f->fs.val.matchtype) |
                      FW_FILTER_WR_MATCHTYPEM_V(f->fs.mask.matchtype));
        fwr->ptcl = f->fs.val.proto;
        fwr->ptclm = f->fs.mask.proto;
        fwr->ttyp = f->fs.val.tos;
        fwr->ttypm = f->fs.mask.tos;
        fwr->ivlan = htons(f->fs.val.ivlan);
        fwr->ivlanm = htons(f->fs.mask.ivlan);
        fwr->ovlan = htons(f->fs.val.ovlan);
        fwr->ovlanm = htons(f->fs.mask.ovlan);
        memcpy(fwr->lip, f->fs.val.lip, sizeof(fwr->lip));
        memcpy(fwr->lipm, f->fs.mask.lip, sizeof(fwr->lipm));
        memcpy(fwr->fip, f->fs.val.fip, sizeof(fwr->fip));
        memcpy(fwr->fipm, f->fs.mask.fip, sizeof(fwr->fipm));
        fwr->lp = htons(f->fs.val.lport);
        fwr->lpm = htons(f->fs.mask.lport);
        fwr->fp = htons(f->fs.val.fport);
        fwr->fpm = htons(f->fs.mask.fport);

        if (adapter->params.filter2_wr_support) {
                fwr->filter_type_swapmac =
                         FW_FILTER2_WR_SWAPMAC_V(f->fs.swapmac);
                fwr->natmode_to_ulp_type =
                        FW_FILTER2_WR_ULP_TYPE_V(f->fs.nat_mode ?
                                                 ULP_MODE_TCPDDP :
                                                 ULP_MODE_NONE) |
                        FW_FILTER2_WR_NATMODE_V(f->fs.nat_mode);
                memcpy(fwr->newlip, f->fs.nat_lip, sizeof(fwr->newlip));
                memcpy(fwr->newfip, f->fs.nat_fip, sizeof(fwr->newfip));
                fwr->newlport = htons(f->fs.nat_lport);
                fwr->newfport = htons(f->fs.nat_fport);
                fwr->natseqcheck = 0;
                fwr->rocev2_qpn = htonl(FW_FILTER2_WR_ROCEV2_V(f->fs.val.roce) |
                                        FW_FILTER2_WR_QPN_V(f->fs.val.rocev2_qpn));
        }

        /* Mark the filter as "pending" and ship off the Filter Work Request.
         * When we get the Work Request Reply we'll clear the pending status.
         */
        f->pending = 1;
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, f->fs.val.iport & 0x3);
	t4_ofld_send(adapter, skb);
        return 0;
}

/* Use cxgb4_filter_normal_create() for creating MAFO failover filter.
 * For other filters, continue using cxgb4_filter_create().
 */

static int cxgb4_filter_normal_create(struct net_device *dev, u32 filter_id,
                                      struct ch_filter_specification *fs,
                                      struct filter_ctx *ctx, gfp_t flags)
{
        struct adapter *adapter = netdev2adap(dev);
	unsigned int fidx, fid_bit = 0;
        struct filter_entry *f;
	unsigned int chip_ver;
        int iq, ret;


	chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);
	if ((filter_id != (adapter->tids.nftids + adapter->tids.nsftids +
			   adapter->tids.nhpftids - 1)) &&
	    (filter_id >= adapter->tids.nftids + adapter->tids.nhpftids))
		return -E2BIG;
        iq = cxgb4_filter_get_steerq(dev, fs);
        if (iq < 0)
                return iq;

	/* IPv6 filters occupy four slots and must be aligned on
	 * four-slot boundaries.  IPv4 filters only occupy a single
	 * slot and have no alignment requirements but writing a new
	 * IPv4 filter into the middle of an existing IPv6 filter
	 * requires clearing the old IPv6 filter.
         */
	if (fs->type == 0) { /* IPv4 */
		/* For T6, If our IPv4 filter isn't being written to a
		 * multiple of two filter index and there's an IPv6
		 * filter at the multiple of 2 base slot, then we need
		 * to delete that IPv6 filter ...
		 * For adapters below T6, IPv6 filter occupies 4 entries.
		 * Hence we need to delete the filter in multiple of 4 slot.
		 */
		if (chip_ver < CHELSIO_T6)
			fidx = filter_id & ~0x3;
		else
			fidx = filter_id & ~0x1;

		if (fidx != filter_id &&
		    adapter->tids.ftid_tab[fidx].fs.type) {
			f = &adapter->tids.ftid_tab[fidx];
			if (f->valid) {
				pr_err("%s: IPv6 filter present at index %d. Please remove IPv6 filter first.\n",
				       __func__, filter_id);
				return -EBUSY;
			}
		}
	} else { /* IPv6 */
		if (chip_ver < CHELSIO_T6) {
			/* Ensure that the IPv6 filter is aligned on a
			 * multiple of 4 boundary.
			 */
			if (filter_id & 0x3)
				return -EINVAL;

			/* Check all except the base overlapping IPv4 filter
			 * slots.
			 */
			fidx = filter_id + 1;
			while (fidx < filter_id + 4) {
				f = &adapter->tids.ftid_tab[fidx];
				if (f->valid) {
					pr_err("%s: IPv6 filter requires 4 indices. IPv4 filter already present at %d. Please remove IPv4 filter first.\n",
					       __func__, fidx);
					return -EBUSY;
				}
				fidx += 4;
                        }
                } else {
			/* For T6+, CLIP being enabled, IPv6 filter would occupy
			 * 2 entries.
			 */
			if (filter_id & 0x1)
                                return -EINVAL;

			/* Check overlapping IPv4 filter slot */
			fidx = filter_id + 1;
			f = &adapter->tids.ftid_tab[fidx];
			if (f->valid) {
				pr_err("%s: IPv6 filter requires 2 indices. IPv4 filter already present at %d. Please remove IPv4 filter first.\n",
				       __func__, fidx);
				return -EBUSY;
                        }
                }
        }

	/* Check to make sure that provided filter index is not
	 * already in use by someone else
	 */
	f = &adapter->tids.ftid_tab[filter_id];
	if (f->valid)
		return -EBUSY;

	/* Hi priority filter index should be from 0 to nhpftids - 1 and
	 * normal priority filter index should be from nhpftids to
	 * nhpftids + nftids - 1.
	 */
	if (chip_ver > CHELSIO_T5 && fs->prio) {
		if (filter_id >= adapter->tids.nhpftids)
			return -EINVAL;
		fidx = filter_id + adapter->tids.hpftid_base;
	} else {
		if (chip_ver > CHELSIO_T5 && filter_id < adapter->tids.nhpftids)
			return -EINVAL;
		fidx = filter_id - adapter->tids.nhpftids +
		       adapter->tids.ftid_base;
	}

	if (chip_ver > CHELSIO_T5 && fs->prio) {
		ret = cxgb4_set_hpftid(&adapter->tids, filter_id,
				       fs->type ? PF_INET6 : PF_INET, chip_ver);
	} else {
		fid_bit = filter_id - adapter->tids.nhpftids;
		ret = cxgb4_set_ftid(&adapter->tids, fid_bit,
				     fs->type ? PF_INET6 : PF_INET, chip_ver);
	}
	if (ret)
		return ret;

	/* Check to make sure the filter requested is writable ...
	 */
	ret = cxgb4_filter_writable(f);
	if (ret)
		goto free_tid;

        /* Convert the filter specification into our internal format.
         * We copy the PF/VF specification into the Outer VLAN field
         * here so the rest of the code -- including the interface to
         * the firmware -- doesn't have to constantly do these checks.
         */
        f->fs = *fs;
        f->fs.iq = iq;
        f->dev = dev;

        ret = cxgb4_filter_match_parse(adapter, f);
        if (ret)
                goto free_tid;

        ret = cxgb4_filter_action_parse(adapter, f);
        if (ret)
		goto free_tid;

        /* Attempt to set the filter.  If we don't succeed, we clear
         * it and return the failure.
         */
        f->ctx = ctx;
        f->tid = fidx; /* Save the actual tid */
	ret = cxgb4_filter_normal_create_wr(adapter, filter_id, GFP_KERNEL);
	if (ret) {
		if (chip_ver > CHELSIO_T5 && f->fs.prio)
			fid_bit = f->tid - adapter->tids.hpftid_base;
		else
			fid_bit = f->tid - adapter->tids.ftid_base;

		goto free_filter;
	}

	return 0;

free_filter:
        cxgb4_filter_clear(adapter, f);
free_tid:
	if (chip_ver > CHELSIO_T5 && f->fs.prio)
		cxgb4_clear_hpftid(&adapter->tids, fid_bit,
				   fs->type ? PF_INET6 : PF_INET, chip_ver);
	else
		cxgb4_clear_ftid(&adapter->tids, fid_bit,
				 fs->type ? PF_INET6 : PF_INET, chip_ver);

        return ret;
}

/* Delete the filter at a specified index.
 */
static int cxgb4_filter_normal_delete_wr(struct adapter *adapter, u32 fidx,
					 gfp_t gfp_mask)
{
	struct filter_entry *f = &adapter->tids.ftid_tab[fidx];
        struct fw_filter_wr *fwr;
        struct sk_buff *skb;
        unsigned int len;

        len = sizeof(*fwr);

        if (gfp_mask & GFP_ATOMIC) {
                skb = alloc_skb(len, GFP_ATOMIC);
                if (!skb)
                        return -ENOMEM;
        } else {
                skb = alloc_skb(len, gfp_mask | __GFP_NOFAIL);
        }

        fwr = (struct fw_filter_wr *)__skb_put(skb, len);
        t4_mk_filtdelwr(f->tid, fwr, adapter->sge.fw_evtq.abs_id);

        /* Mark the filter as "pending" and ship off the Filter Work Request.
         * When we get the Work Request Reply we'll clear the pending status.
         */
        f->pending = 1;
        t4_mgmt_tx(adapter, skb);
        return 0;
}

static int cxgb4_filter_normal_delete(struct net_device *dev, u32 filter_id,
                                      struct filter_ctx *ctx, gfp_t flags)
{
        struct adapter *adapter = netdev2adap(dev);
        struct filter_entry *f;
	unsigned int chip_ver;
        int ret;

        chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);
        /* Make sure this is a valid filter and that we can delete it.
         */
	if ((filter_id != (adapter->tids.nftids + adapter->tids.nsftids +
			   adapter->tids.nhpftids - 1)) &&
	    (filter_id >= adapter->tids.nftids + adapter->tids.nhpftids))
		return -E2BIG;

	f = &adapter->tids.ftid_tab[filter_id];

        ret = cxgb4_filter_writable(f);
        if (ret)
                return ret;

	if (f->valid) {
		f->ctx = ctx;
		if (chip_ver > CHELSIO_T5 && f->fs.prio)
			cxgb4_clear_hpftid(&adapter->tids,
					   f->tid - adapter->tids.hpftid_base,
					   f->fs.type ? PF_INET6 : PF_INET,
					   chip_ver);
		else
			cxgb4_clear_ftid(&adapter->tids,
					 f->tid - adapter->tids.ftid_base,
					 f->fs.type ? PF_INET6 : PF_INET,
					 chip_ver);
		return cxgb4_filter_normal_delete_wr(adapter, filter_id,
						     GFP_KERNEL);
	}

	/*
	 * If the caller has passed in a Completion Context then we need to
	 * mark it as a successful completion so they don't stall waiting
	 * for it.
	 */
	if (ctx) {
		ctx->result = 0;
		complete(&ctx->completion);
	}
	return 0;
}

/* Handle a filter write/deletion reply.
 */
void cxgb4_filter_normal_rpl(struct adapter *adap,
			     const struct cpl_set_tcb_rpl *rpl)
{
        unsigned int ret = TCB_COOKIE_G(rpl->cookie);
        unsigned int tid = GET_TID(rpl);
	struct filter_entry *f = NULL;
        struct filter_ctx *ctx;

	int idx, max_fidx;

	max_fidx = adap->tids.nftids + adap->tids.nsftids +
		   adap->tids.nhpftids;
	/* Get the corresponding filter entry for this tid */
	if (adap->tids.ftid_tab) {
		/* Check this in hi-prio filter region */
		idx = tid - adap->tids.hpftid_base;
		if (idx < adap->tids.nhpftids) {
			f = &adap->tids.ftid_tab[idx];
			if (f->tid != tid)
				return;
		} else {
			/* Check this in normal filter region */
			idx = tid - adap->tids.ftid_base + adap->tids.nhpftids;
			if (idx >= max_fidx)
				return;
			f = &adap->tids.ftid_tab[idx];
			if (f->tid != tid)
				return;
		}
	}

        /* We did not find the filter entry for this tid */
        if (!f)
                return;

        /* Pull off any filter operation context attached to the
         * filter.
         */
        ctx = f->ctx;
        f->ctx = NULL;

        switch (ret) {
        case FW_FILTER_WR_FLT_DELETED:
                /* Clear the filter when we get confirmation from the
                 * hardware that the filter has been deleted.
                 */
		cxgb4_ftid_filter_clear(adap, f);
		if (ctx)
                        ctx->result = 0;
                break;
        case FW_FILTER_WR_FLT_ADDED:
                f->pending = 0;  /* Asynchronous setup completed */
                f->valid = 1;
                if (ctx) {
                        ctx->result = 0;
			ctx->tid = idx;
                }
                break;
        default:
                /* Something went wrong.  Issue a warning about the
                 * problem and clear everything out.
                 */
                dev_err(adap->pdev_dev, "filter %u setup failed with error %u\n",
                       f->tid, ret);
                cxgb4_ftid_filter_clear(adap, f);
                if (ctx)
                        ctx->result = -EINVAL;
                break;
        }

        if (ctx)
                complete(&ctx->completion);
}

/* Hash Filters
 */
static u64 cxgb4_filter_hash_ntuple(struct ch_filter_specification *fs,
                                    struct net_device *dev)
{
        struct adapter *adap = netdev2adap(dev);
        struct tp_params *tp = &adap->params.tp;
        u64 ntuple = 0;

        /* Initialize each of the fields which we care about which are present
         * in the Compressed Filter Tuple.
         */
        if (tp->vlan_shift >= 0 && fs->mask.ivlan)
                ntuple |= (u64)(FT_VLAN_VLD_F | fs->val.ivlan) << tp->vlan_shift;

        if (tp->port_shift >= 0 && fs->mask.iport)
                ntuple |= (u64)fs->val.iport << tp->port_shift;

        if (tp->protocol_shift >= 0) {
                if (!fs->val.proto)
                        ntuple |= (u64)IPPROTO_TCP << tp->protocol_shift;
                else
                        ntuple |= (u64)fs->val.proto << tp->protocol_shift;
        }

        if (tp->tos_shift >= 0 && fs->mask.tos)
                ntuple |= (u64)(fs->val.tos) << tp->tos_shift;

        if (tp->vnic_shift >= 0) {
                if ((adap->params.tp.ingress_config & USE_ENC_IDX_F) &&
                    fs->mask.encap_vld)
                        ntuple |= (u64)((fs->val.encap_vld << 16) |
                                        (fs->val.ovlan)) << tp->vnic_shift;
                else if ((adap->params.tp.ingress_config & VNIC_F) &&
                         fs->mask.pfvf_vld)
                        ntuple |= (u64)((fs->val.pfvf_vld << 16) |
                                        (fs->val.pf << 13) |
                                        (fs->val.vf)) << tp->vnic_shift;
                else
                        ntuple |= (u64)((fs->val.ovlan_vld << 16) |
                                        (fs->val.ovlan)) << tp->vnic_shift;
        }

        if (tp->macmatch_shift >= 0 && fs->mask.macidx)
                ntuple |= (u64)(fs->val.macidx) << tp->macmatch_shift;

        if (tp->ethertype_shift >= 0 && fs->mask.ethtype)
                ntuple |= (u64)(fs->val.ethtype) << tp->ethertype_shift;

        if (tp->matchtype_shift >= 0 && fs->mask.matchtype)
                ntuple |= (u64)(fs->val.matchtype) << tp->matchtype_shift;

        if (tp->frag_shift >= 0 && fs->mask.frag)
                ntuple |= (u64)(fs->val.frag) << tp->frag_shift;

        if (tp->fcoe_shift >= 0 && fs->mask.fcoe)
                ntuple |= (u64)(fs->val.fcoe) << tp->fcoe_shift;

        if (tp->ipsecidx_shift >= 0 && fs->mask.ipsecidx)
                ntuple |= (u64)(fs->val.ipsecidx) << tp->ipsecidx_shift;

        if (tp->roce_shift >= 0 && fs->mask.roce)
                ntuple |= (u64)(fs->val.roce) << tp->roce_shift;

        if (tp->synonly_shift >= 0 && fs->mask.synonly)
                ntuple |= (u64)(fs->val.synonly) << tp->synonly_shift;

        if (tp->tcpflags_shift >= 0 && fs->mask.tcpflags)
                ntuple |= (u64)(fs->val.tcpflags) << tp->tcpflags_shift;

        return ntuple;
}

static void cxgb4_filter_hash_mk_act_open_req6(struct filter_entry *f,
                                               struct sk_buff *skb,
                                               u32 qid_filterid)
{
        struct adapter *adap = netdev2adap(f->dev);
        struct cpl_t5_act_open_req6 *t5req = NULL;
        struct cpl_t6_act_open_req6 *t6req = NULL;
        struct cpl_t7_act_open_req6 *t7req = NULL;
        struct cpl_act_open_req6 *req = NULL;
        u32 chip_ver, opt2;
        u64 ntuple, opt0;

        chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
        ntuple = cxgb4_filter_hash_ntuple(&f->fs, f->dev);

        opt0 = NAGLE_V(f->fs.newvlan == VLAN_REMOVE ||
                       f->fs.newvlan == VLAN_REWRITE) |
               DELACK_V(f->fs.hitcnts) |
               L2T_IDX_V(f->l2t ? f->l2t->idx : 0) |
               SMAC_SEL_V((cxgb4_port_viid(f->dev) & 0x7F) << 1) |
               TX_CHAN_V(cxgb4_hash_filter_get_tx_chan(adap, f)) |
               NO_CONG_V(f->fs.rpttid) |
               ULP_MODE_V(f->fs.nat_mode ? ULP_MODE_TCPDDP : ULP_MODE_NONE) |
               TCAM_BYPASS_F | NON_OFFLOAD_F;

        opt2 = RSS_QUEUE_VALID_F | RSS_QUEUE_V(f->fs.iq) |
               TX_QUEUE_V(f->fs.nat_mode) |
	       T5_OPT_2_VALID_F |
               RX_CHANNEL_V(cxgb4_hash_filter_get_rx_chan(adap, f)) |
               SACK_EN_V(f->fs.swapmac) |
               PACE_V((f->fs.maskhash) | ((f->fs.dirsteerhash) << 1));

        switch (chip_ver) {
        case CHELSIO_T5:
                t5req = (struct cpl_t5_act_open_req6 *)__skb_put(skb,
                                                                sizeof(*t5req));
                INIT_TP_WR(t5req, 0);
                t5req->params = cpu_to_be64(FILTER_TUPLE_V(ntuple));
                t5req->opt0 = cpu_to_be64(opt0);
                t5req->opt2 = cpu_to_be32(opt2);
                req = (struct cpl_act_open_req6 *)t5req;
                break;
        case CHELSIO_T6:
                t6req = (struct cpl_t6_act_open_req6 *)__skb_put(skb,
                                                                sizeof(*t6req));
                INIT_TP_WR(t6req, 0);
                req = (struct cpl_act_open_req6 *)t6req;
                t6req->params = cpu_to_be64(FILTER_TUPLE_V(ntuple));
                t6req->opt0 = cpu_to_be64(opt0);
                t6req->opt2 = cpu_to_be32(opt2);
                break;
        case CHELSIO_T7:
                t7req = (struct cpl_t7_act_open_req6 *)__skb_put(skb,
                                                                sizeof(*t7req));
                INIT_TP_WR(t7req, 0);
                t7req->params = cpu_to_be64(T7_FILTER_TUPLE_V(ntuple));
                t7req->opt0 = cpu_to_be64(opt0);
                t7req->opt2 = cpu_to_be32(opt2);
                req = (struct cpl_act_open_req6 *)t7req;
                break;
        default:
                pr_err("%s: unsupported chip type!\n", __func__);
                return;
        }

        OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_ACT_OPEN_REQ6, qid_filterid));
        req->local_port = cpu_to_be16(f->fs.val.lport);
        req->peer_port = cpu_to_be16(f->fs.val.fport);
        req->local_ip_hi = *(__be64 *)(&f->fs.val.lip);
        req->local_ip_lo = *(((__be64 *)&f->fs.val.lip) + 1);
        req->peer_ip_hi = *(__be64 *)(&f->fs.val.fip);
        req->peer_ip_lo = *(((__be64 *)&f->fs.val.fip) + 1);
}

static void cxgb4_filter_hash_mk_act_open_req(struct filter_entry *f,
                                              struct sk_buff *skb,
                                              u32 qid_filterid)
{
        struct adapter *adap = netdev2adap(f->dev);
        struct cpl_t5_act_open_req *t5req = NULL;
        struct cpl_t6_act_open_req *t6req = NULL;
        struct cpl_t7_act_open_req *t7req = NULL;
        struct cpl_act_open_req *req = NULL;
        u32 chip_ver, opt2;
        u64 ntuple, opt0;

        chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
        ntuple = cxgb4_filter_hash_ntuple(&f->fs, f->dev);

        opt0 = NAGLE_V(f->fs.newvlan == VLAN_REMOVE ||
                       f->fs.newvlan == VLAN_REWRITE) |
               DELACK_V(f->fs.hitcnts) |
               L2T_IDX_V(f->l2t ? f->l2t->idx : 0) |
               SMAC_SEL_V((cxgb4_port_viid(f->dev) & 0x7F) << 1) |
               TX_CHAN_V(cxgb4_hash_filter_get_tx_chan(adap, f)) |
               NO_CONG_V(f->fs.rpttid) |
               ULP_MODE_V(f->fs.nat_mode ? ULP_MODE_TCPDDP : ULP_MODE_NONE) |
               TCAM_BYPASS_F | NON_OFFLOAD_F;

        opt2 = RSS_QUEUE_VALID_F | RSS_QUEUE_V(f->fs.iq) |
               TX_QUEUE_V(f->fs.nat_mode) |
	       T5_OPT_2_VALID_F |
               RX_CHANNEL_V(cxgb4_hash_filter_get_rx_chan(adap, f)) |
               SACK_EN_V(f->fs.swapmac) |
               PACE_V((f->fs.maskhash) | ((f->fs.dirsteerhash) << 1));

        switch (chip_ver) {
        case CHELSIO_T5:
                t5req = (struct cpl_t5_act_open_req *)__skb_put(skb,
                                                                sizeof(*t5req));
                INIT_TP_WR(t5req, 0);
                t5req->params = cpu_to_be64(FILTER_TUPLE_V(ntuple));
                t5req->opt0 = cpu_to_be64(opt0);
                t5req->opt2 = cpu_to_be32(opt2);
                req = (struct cpl_act_open_req *)t5req;
                break;
        case CHELSIO_T6:
                t6req = (struct cpl_t6_act_open_req *)__skb_put(skb,
                                                                sizeof(*t6req));
                INIT_TP_WR(t6req, 0);
                req = (struct cpl_act_open_req *)t6req;
                t6req->params = cpu_to_be64(FILTER_TUPLE_V(ntuple));
                t6req->opt0 = cpu_to_be64(opt0);
                t6req->opt2 = cpu_to_be32(opt2);
                break;
        case CHELSIO_T7:
                t7req = (struct cpl_t7_act_open_req *)__skb_put(skb,
                                                                sizeof(*t7req));
                INIT_TP_WR(t7req, 0);
                t7req->params = cpu_to_be64(T7_FILTER_TUPLE_V(ntuple));
                t7req->opt0 = cpu_to_be64(opt0);
                t7req->opt2 = cpu_to_be32(opt2);
                req = (struct cpl_act_open_req *)t7req;
                break;
        default:
                pr_err("%s: unsupported chip type!\n", __func__);
                return;
        }

        OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_ACT_OPEN_REQ, qid_filterid));
        req->local_port = cpu_to_be16(f->fs.val.lport);
        req->peer_port = cpu_to_be16(f->fs.val.fport);
        req->local_ip = f->fs.val.lip[0] | (f->fs.val.lip[1] << 8) |
                        (f->fs.val.lip[2] << 16) | (f->fs.val.lip[3] << 24);
        req->peer_ip = f->fs.val.fip[0] | (f->fs.val.fip[1] << 8) |
                       (f->fs.val.fip[2] << 16) | (f->fs.val.fip[3] << 24);
}

static int cxgb4_filter_hash_create(struct net_device *dev,
                                    struct ch_filter_specification *fs,
                                    struct filter_ctx *ctx, gfp_t flags)
{
        struct adapter *adapter = netdev2adap(dev);
	struct tid_info *t = &adapter->tids;
        const struct hlist_nulls_node *node;
        u32 hash, slot, fw_qid, atid, size;
        struct filter_ehash_bucket *head;
        struct filter_entry *f = NULL;
        unsigned int chip_ver;
        struct sk_buff *skb;
        int iq, ret;

        chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);

        iq = cxgb4_filter_get_steerq(dev, fs);
        if (iq < 0)
                return iq;

        /* lookup for an existing entry if its a T6+ */
        if (chip_ver >= CHELSIO_T6) {
                if (fs->type) {
                        const struct in6_addr *laddr = (struct in6_addr *)fs->val.lip;
                        const struct in6_addr *faddr = (struct in6_addr *)fs->val.fip;
                        u32 lhash, fhash;
                        u32 ports = (((u32)fs->val.lport) << 16) |
                                    (__force u32)fs->val.fport;

                        lhash = (__force u32)laddr->s6_addr32[3];
                        fhash = __ipv6_addr_jhash(faddr, 0);
                        hash = jhash_3words(lhash, fhash, ports,
                                            cxgb4_filter_hash_ntuple(fs, dev) &
                                            0xFFFFFFFF);
                } else {
                        u32 lip = fs->val.lip[0] | fs->val.lip[1] << 8 |
                                  fs->val.lip[2] << 16 | fs->val.lip[3] << 24;
                        u32 fip = fs->val.fip[0] | fs->val.fip[1] << 8 |
                                  fs->val.fip[2] << 16 | fs->val.fip[3] << 24;

                        hash = jhash_3words((__force __u32)lip,
                                            (__force __u32)fip,
                                            ((__u32)fs->val.lport) << 16 |
                                            (__force __u32)fs->val.fport,
                                            cxgb4_filter_hash_ntuple(fs, dev) &
                                            0xFFFFFFFF);
                }

                rcu_read_lock();
begin:
                hlist_nulls_for_each_entry_rcu(f, node, &head->chain, filter_nulls_node) {
                        u8 lip = memcmp(f->fs.val.lip, fs->val.lip,
                                        sizeof(fs->val.lip));
                        u8 fip = memcmp(f->fs.val.fip, fs->val.fip,
                                        sizeof(fs->val.fip));

                        if (f->filter_hash == hash &&
                            f->fs.val.lport == fs->val.lport &&
                            f->fs.val.fport == fs->val.fport &&
                            !lip && !fip) {
                                rcu_read_unlock();
                                return -EEXIST;
                        }
                }
                /* If the nulls value we got at the end of this lookup is
                 * not the expected one, we must restart lookup.
                 * We probably met an item that was moved to another chain.
                 */
                if (get_nulls_value(node) != slot)
                        goto begin;

                rcu_read_unlock();
        }

        f = kzalloc(sizeof(*f), flags);
	if (!f) {
		ret = -ENOMEM;
		goto out_err;
	}

        f->fs = *fs;
        f->ctx = ctx;
        f->dev = dev;
        f->fs.iq = iq;

        ret = cxgb4_filter_match_parse(adapter, f);
        if (ret)
                goto out_err;

        ret = cxgb4_filter_action_parse(adapter, f);
        if (ret)
                goto out_err;

	atid = cxgb4_alloc_atid(t, f);
        if (atid < 0)
                goto out_filter_free;

        fw_qid = adapter->sge.fw_evtq.abs_id;
        if (f->fs.type) {
                switch (chip_ver) {
                case CHELSIO_T5:
                        size = sizeof(struct cpl_t5_act_open_req6);
                        break;
                case CHELSIO_T6:
                        size = sizeof(struct cpl_t6_act_open_req6);
                        break;
                default:
                        size = sizeof(struct cpl_t7_act_open_req6);
                        break;
                }

                skb = alloc_skb(size, flags);
                if (!skb) {
                        ret = -ENOMEM;
                        goto out_free_atid;
                }

                cxgb4_filter_hash_mk_act_open_req6(f, skb,
                                                   (fw_qid << 14) | atid);
        } else {
                switch (chip_ver) {
                case CHELSIO_T5:
                        size = sizeof(struct cpl_t5_act_open_req);
                        break;
                case CHELSIO_T6:
                        size = sizeof(struct cpl_t6_act_open_req);
                        break;
                default:
                        size = sizeof(struct cpl_t7_act_open_req);
                        break;
                }

                skb = alloc_skb(size, flags);
                if (!skb) {
                        ret = -ENOMEM;
                        goto out_free_atid;
                }

                cxgb4_filter_hash_mk_act_open_req(f, skb,
                                                  (fw_qid << 14) | atid);
        }

        f->pending = 1;
        set_wr_txq(skb, CPL_PRIORITY_SETUP, f->fs.val.iport & 0x3);
	t4_ofld_send(adapter, skb);
        return 0;

out_free_atid:
	cxgb4_free_atid(t, atid);
out_filter_free:
        cxgb4_filter_clear(adapter, f);
        return ret;

out_err:
        kfree(f);
        return ret;
}

static void cxgb4_filter_hash_mk_abort_req_ulp(struct cpl_abort_req *abort_req,
                                              unsigned int tid)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)abort_req;
	struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);

	txpkt->cmd_dest = htonl(ULPTX_CMD_V(ULP_TX_PKT) | ULP_TXPKT_DEST_V(0));
	txpkt->len = htonl(DIV_ROUND_UP(sizeof(*abort_req), 16));
	sc->cmd_more = htonl(ULPTX_CMD_V(ULP_TX_SC_IMM));
	sc->len = htonl(sizeof(*abort_req) - sizeof(struct work_request_hdr));
	OPCODE_TID(abort_req) = htonl(MK_OPCODE_TID(CPL_ABORT_REQ, tid));
	abort_req->rsvd0 = htonl(0);
	abort_req->rsvd1 = 0;
	abort_req->cmd = CPL_ABORT_NO_RST;
}

static void cxgb4_filter_hash_mk_abort_rpl_ulp(struct cpl_abort_rpl *abort_rpl,
                                               unsigned int tid)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)abort_rpl;
	struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);

	txpkt->cmd_dest = htonl(ULPTX_CMD_V(ULP_TX_PKT) | ULP_TXPKT_DEST_V(0));
	txpkt->len = htonl(DIV_ROUND_UP(sizeof(*abort_rpl), 16));
	sc->cmd_more = htonl(ULPTX_CMD_V(ULP_TX_SC_IMM));
	sc->len = htonl(sizeof(*abort_rpl) - sizeof(struct work_request_hdr));
	OPCODE_TID(abort_rpl) = htonl(MK_OPCODE_TID(CPL_ABORT_RPL, tid));
	abort_rpl->rsvd0 = htonl(0);
	abort_rpl->rsvd1 = 0;
	abort_rpl->cmd = CPL_ABORT_NO_RST;
}

/* Build a CPL_SET_TCB_FIELD message as payload of a ULP_TX_PKT command.
 */
static void cxgb4_filter_hash_mk_set_tcb_field_ulp(struct filter_entry *f,
                                                   struct cpl_set_tcb_field *req,
                                                   unsigned int word,
                                                   u64 mask, u64 val, u8 cookie,
                                                   int no_reply)
{
        struct ulp_txpkt *txpkt = (struct ulp_txpkt *)req;
        struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);
        struct adapter *adap = netdev2adap(f->dev);

        txpkt->cmd_dest = htonl(ULPTX_CMD_V(ULP_TX_PKT) | ULP_TXPKT_DEST_V(0));
        txpkt->len = htonl(DIV_ROUND_UP(sizeof(*req), 16));
        sc->cmd_more = htonl(ULPTX_CMD_V(ULP_TX_SC_IMM));
        sc->len = htonl(sizeof(*req) - sizeof(struct work_request_hdr));
        OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, f->tid));
        if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7)
                req->reply_ctrl = htons(NO_REPLY_V(no_reply) |
                                        T7_REPLY_CHAN_V(0) |
                                        T7_QUEUENO_V(0));
        else
                req->reply_ctrl = htons(NO_REPLY_V(no_reply) |
                                        REPLY_CHAN_V(0) |
                                        QUEUENO_V(0));
        req->word_cookie = htons(TCB_WORD_V(word) | TCB_COOKIE_V(cookie));
        req->mask = cpu_to_be64(mask);
        req->val = cpu_to_be64(val);
        sc = (struct ulptx_idata *)(req + 1);
        sc->cmd_more = htonl(ULPTX_CMD_V(ULP_TX_SC_NOOP));
        sc->len = htonl(0);
}

static int cxgb4_filter_hash_delete(struct net_device *dev, u32 filter_id,
                                    struct filter_ctx *ctx, gfp_t flags)
{
        struct adapter *adapter = netdev2adap(dev);
	struct tid_info *t = &adapter->tids;
        struct filter_entry *f;
        int ret;

	CH_MSG(adapter, INFO, HW, "%s: filter_id = %d ; nftids = %d\n",
	       __func__, filter_id, adapter->tids.nftids);

	if (unlikely(tid_out_of_range(t, filter_id))) {
		CH_ERR(adapter, "%s: hash filter TID %u too large\n",
                       __func__, filter_id);
                return -E2BIG;
        }

	f = lookup_tid(t, filter_id);
        if (!f) {
                CH_ERR(adapter, "%s: no filter entry for filter_id = %d",
                       __func__, filter_id);
                return -EINVAL;
        }

        ret = cxgb4_filter_writable(f);
        if (ret)
                return ret;

	if (f->valid) {
		struct cpl_abort_req *abort_req;
		struct cpl_abort_rpl *abort_rpl;
		struct cpl_set_tcb_field *req;
		struct ulptx_idata *aligner;
		struct work_request_hdr *wr;
		struct sk_buff *skb;
		unsigned int wrlen;

		f->ctx = ctx;
		f->pending = 1;

		wrlen = roundup(sizeof(*wr) + (sizeof(*req) + sizeof(*aligner))
				+ sizeof(*abort_req) + sizeof(*abort_rpl), 16);
		skb = alloc_skb(wrlen, flags);
		if (!skb) {
			CH_ERR(adapter, "%s: could not allocate skb ..\n",
			       __func__);
			goto out_err;
		}

		set_wr_txq(skb, CPL_PRIORITY_CONTROL, f->fs.val.iport & 0x3);
		req = (struct cpl_set_tcb_field *)__skb_put(skb, wrlen);
		INIT_ULPTX_WR(req, wrlen, 0, 0);
		wr = (struct work_request_hdr *)req;
		wr++;
		req = (struct cpl_set_tcb_field *)wr;
		cxgb4_filter_hash_mk_set_tcb_field_ulp(f, req, TCB_RSS_INFO_W,
				TCB_RSS_INFO_V(TCB_RSS_INFO_M),
				TCB_RSS_INFO_V(adapter->sge.fw_evtq.abs_id),
				0, 1);
		aligner = (struct ulptx_idata *)(req + 1);
		abort_req = (struct cpl_abort_req *)(aligner + 1);
		cxgb4_filter_hash_mk_abort_req_ulp(abort_req, f->tid);
		abort_rpl = (struct cpl_abort_rpl *)(abort_req + 1);
		cxgb4_filter_hash_mk_abort_rpl_ulp(abort_rpl, f->tid);
		t4_ofld_send(adapter, skb);
        }


out_err:
	return -ENOMEM;
}

static int set_tcb_field(struct adapter *adap, struct filter_entry *f,
			 u32 ftid,  u16 word, u64 mask, u64 val, int no_reply)
{
	struct cpl_set_tcb_field *req;
	struct sk_buff *skb;

	skb = alloc_skb(sizeof(struct cpl_set_tcb_field), GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	req = (struct cpl_set_tcb_field *)__skb_put_zero(skb, sizeof(*req));
	INIT_TP_WR_CPL(req, CPL_SET_TCB_FIELD, ftid);
	req->reply_ctrl = htons(REPLY_CHAN_V(0) |
				QUEUENO_V(adap->sge.fw_evtq.abs_id) |
				NO_REPLY_V(no_reply));
	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7)
		req->reply_ctrl = htons(T7_REPLY_CHAN_V(0) |
				T7_QUEUENO_V(adap->sge.fw_evtq.abs_id) |
				NO_REPLY_V(no_reply));
	else
		req->reply_ctrl = htons(REPLY_CHAN_V(0) |
				QUEUENO_V(adap->sge.fw_evtq.abs_id) |
				NO_REPLY_V(no_reply));
	req->word_cookie = htons(TCB_WORD_V(word) | TCB_COOKIE_V(ftid));
	req->mask = cpu_to_be64(mask);
	req->val = cpu_to_be64(val);
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, f->fs.val.iport & 0x3);
	t4_ofld_send(adap, skb);
	return 0;
}

/* Set one of the t_flags bits in the TCB.
 */
static void set_tcb_tflag(struct adapter *adap, struct filter_entry *f,
                         u32 ftid, u32 bit_pos, u32 val, int no_reply)
{
       set_tcb_field(adap, f, ftid,  TCB_T_FLAGS_W, 1ULL << bit_pos,
                     (unsigned long long)val << bit_pos, no_reply);
}

static void set_nat_params(struct adapter *adap, struct filter_entry *f,
			   unsigned int tid, bool dip, bool sip, bool dp,
			   bool sp)
{
	u8 *nat_lp = (u8 *)&f->fs.nat_lport;
	u8 *nat_fp = (u8 *)&f->fs.nat_fport;

	if (dip) {
		if (f->fs.type) {
			set_tcb_field(adap, f, tid, TCB_SND_UNA_RAW_W,
				      WORD_MASK, f->fs.nat_lip[15] |
				      f->fs.nat_lip[14] << 8 |
				      f->fs.nat_lip[13] << 16 |
				      (u64)f->fs.nat_lip[12] << 24, 1);

			set_tcb_field(adap, f, tid, TCB_SND_UNA_RAW_W + 1,
				      WORD_MASK, f->fs.nat_lip[11] |
				      f->fs.nat_lip[10] << 8 |
				      f->fs.nat_lip[9] << 16 |
				      (u64)f->fs.nat_lip[8] << 24, 1);

			set_tcb_field(adap, f, tid, TCB_SND_UNA_RAW_W + 2,
				      WORD_MASK, f->fs.nat_lip[7] |
				      f->fs.nat_lip[6] << 8 |
				      f->fs.nat_lip[5] << 16 |
				      (u64)f->fs.nat_lip[4] << 24, 1);

			set_tcb_field(adap, f, tid, TCB_SND_UNA_RAW_W + 3,
				      WORD_MASK, f->fs.nat_lip[3] |
				      f->fs.nat_lip[2] << 8 |
				      f->fs.nat_lip[1] << 16 |
				      (u64)f->fs.nat_lip[0] << 24, 1);
		} else {
			set_tcb_field(adap, f, tid, TCB_RX_FRAG3_LEN_RAW_W,
				      WORD_MASK, f->fs.nat_lip[3] |
				      f->fs.nat_lip[2] << 8 |
				      f->fs.nat_lip[1] << 16 |
				      (u64)f->fs.nat_lip[0] << 24, 1);
		}
	}

	if (sip) {
		if (f->fs.type) {
			set_tcb_field(adap, f, tid, TCB_RX_FRAG2_PTR_RAW_W,
				      WORD_MASK, f->fs.nat_fip[15] |
				      f->fs.nat_fip[14] << 8 |
				      f->fs.nat_fip[13] << 16 |
				      (u64)f->fs.nat_fip[12] << 24, 1);

			set_tcb_field(adap, f, tid, TCB_RX_FRAG2_PTR_RAW_W + 1,
				      WORD_MASK, f->fs.nat_fip[11] |
				      f->fs.nat_fip[10] << 8 |
				      f->fs.nat_fip[9] << 16 |
				      (u64)f->fs.nat_fip[8] << 24, 1);

			set_tcb_field(adap, f, tid, TCB_RX_FRAG2_PTR_RAW_W + 2,
				      WORD_MASK, f->fs.nat_fip[7] |
				      f->fs.nat_fip[6] << 8 |
				      f->fs.nat_fip[5] << 16 |
				      (u64)f->fs.nat_fip[4] << 24, 1);

			set_tcb_field(adap, f, tid, TCB_RX_FRAG2_PTR_RAW_W + 3,
				      WORD_MASK, f->fs.nat_fip[3] |
				      f->fs.nat_fip[2] << 8 |
				      f->fs.nat_fip[1] << 16 |
				      (u64)f->fs.nat_fip[0] << 24, 1);

		} else {
			set_tcb_field(adap, f, tid,
				      TCB_RX_FRAG3_START_IDX_OFFSET_RAW_W,
				      WORD_MASK, f->fs.nat_fip[3] |
				      f->fs.nat_fip[2] << 8 |
				      f->fs.nat_fip[1] << 16 |
				      (u64)f->fs.nat_fip[0] << 24, 1);
		}
	}

	set_tcb_field(adap, f, tid, TCB_PDU_HDR_LEN_W, WORD_MASK,
		      (dp ? (nat_lp[1] | nat_lp[0] << 8) : 0) |
		      (sp ? (nat_fp[1] << 16 | (u64)nat_fp[0] << 24) : 0),
		      1);
}

void cxgb4_filter_hash_create_rpl(struct adapter *adap,
                                  const struct cpl_act_open_rpl *rpl)
{
        unsigned int ftid = TID_TID_G(AOPEN_ATID_G(ntohl(rpl->atid_status)));
        unsigned int status  = AOPEN_STATUS_G(ntohl(rpl->atid_status));
	struct tid_info *t = &adap->tids;
        struct filter_ehash_bucket *head;
        unsigned int tid = GET_TID(rpl);
        struct hlist_nulls_head *list;
        struct filter_ctx *ctx = NULL;
        struct filter_entry *f;
        spinlock_t *lock; /* Lock for accessing ehash table */

        CH_MSG(adap, INFO, HW,
               "%s: tid = %u; atid = %u; status = %u\n",
               __func__, tid, ftid, status);

#ifdef CONFIG_PO_FCOE
        /* ATID is 14 bit value [0..13], MAX_ATIDS is 8192
         * ATID needs max 13 bits [0..12], using 13th bit in
         * ATID for FCoE CPL_ACT_OPEN_REQ.
         */
        if (ftid & BIT(CXGB_FCOE_ATID)) {
                cxgb_fcoe_cpl_act_open_rpl(adap, ftid, tid, status);
                return;
        }
#endif

	f = lookup_atid(t, ftid);
        if (!f) {
                CH_WARN_RATELIMIT(adap, "%s:could not find filter entry",
                                  __func__);
                return;
        }

        ctx = f->ctx;
        f->ctx = NULL;

        if (status != CPL_ERR_NONE) {
                CH_WARN_RATELIMIT(adap,
                                  "%s: filter creation PROBLEM; status = %u\n",
                                  __func__, status);

                cxgb4_free_atid(t, ftid);
                if (ctx) {
                        if (status == CPL_ERR_TCAM_FULL)
                                ctx->result = -EAGAIN;
                        else
                                ctx->result = -EINVAL;
                }
                goto out_complete;
        }

        /* Hash 4-tuple and add filter entry */
        if (f->fs.type) {
                if (is_t5(adap->params.chip)) {
			u32 lip = f->fs.val.lip[0] | f->fs.val.lip[1] << 8 |
				f->fs.val.lip[2] << 16 | f->fs.val.lip[3] << 24;
			u32 fip = f->fs.val.fip[0] | f->fs.val.fip[1] << 8 |
				f->fs.val.fip[2] << 16 | f->fs.val.fip[3] << 24;

                        f->filter_hash = inet_ehashfn(dev_net(f->dev), lip,
                                                          f->fs.val.lport, fip,
                                                          f->fs.val.fport);
                } else {
                        const struct in6_addr *laddr = (struct in6_addr *)f->fs.val.lip;
                        const struct in6_addr *faddr = (struct in6_addr *)f->fs.val.fip;
                        u32 ports = (((u32)f->fs.val.lport) << 16) |
                                    (__force u32)f->fs.val.fport;
                        u32 lhash, fhash;

                        lhash = (__force u32)laddr->s6_addr32[3];
                        fhash = __ipv6_addr_jhash(faddr, 0);
                        f->filter_hash = jhash_3words(lhash, fhash, ports,
                                                      cxgb4_filter_hash_ntuple(&f->fs, f->dev) &
                                                      0xFFFFFFFF);
                }
        } else {
                u32 lip = f->fs.val.lip[0] | f->fs.val.lip[1] << 8 |
                          f->fs.val.lip[2] << 16 | f->fs.val.lip[3] << 24;
                u32 fip = f->fs.val.fip[0] | f->fs.val.fip[1] << 8 |
                          f->fs.val.fip[2] << 16 | f->fs.val.fip[3] << 24;

                if (is_t5(adap->params.chip))
                        f->filter_hash = inet_ehashfn(dev_net(f->dev), lip,
                                                      f->fs.val.lport, fip,
                                                      f->fs.val.fport);
                else
                        f->filter_hash = jhash_3words((__force __u32)lip,
                                                      (__force __u32)fip,
                                                      ((__u32)f->fs.val.lport) << 16 |
                                                      (__force __u32)f->fs.val.fport,
                                                      cxgb4_filter_hash_ntuple(&f->fs, f->dev) &
                                                      0xFFFFFFFF);
        }

        spin_lock_bh(lock);
        list = &head->chain;
        hlist_nulls_add_head_rcu(&f->filter_nulls_node, list);

	/* Store tid value in special filter entry field */
	f->tid = tid;
	f->pending = 0;  /* Asynchronous setup completed */
	f->valid = 1;
        spin_unlock_bh(lock);
	cxgb4_insert_tid(t, f, f->tid, 0);
	cxgb4_free_atid(t, ftid);
        if (ctx) {
                ctx->tid = f->tid;
                ctx->result = 0;
        }

        if (f->fs.hitcnts) {
                set_tcb_field(adap, f, tid, TCB_TIMESTAMP_W,
                              TCB_TIMESTAMP_V(TCB_TIMESTAMP_M),
                              TCB_TIMESTAMP_V(0ULL), 1);
                set_tcb_field(adap, f, tid, TCB_T_RTT_TS_RECENT_AGE_W,
                              TCB_T_RTT_TS_RECENT_AGE_V(TCB_T_RTT_TS_RECENT_AGE_M),
                              TCB_T_RTT_TS_RECENT_AGE_V(0ULL), 1);
        }

        if (f->fs.newdmac)
                set_tcb_tflag(adap, f, tid, TF_CCTRL_ECE_S, 1, 1);

        if (f->fs.newvlan == VLAN_INSERT || f->fs.newvlan == VLAN_REWRITE)
                set_tcb_tflag(adap, f, tid, TF_CCTRL_RFR_S, 1, 1);

        if (f->fs.newsmac) {
                set_tcb_field(adap, f, tid, TCB_SMAC_SEL_W,
                              TCB_SMAC_SEL_V(TCB_SMAC_SEL_M),
                              TCB_SMAC_SEL_V(f->smtidx), 1);
                set_tcb_tflag(adap, f, tid, TF_CCTRL_CWR_S, 1, 1);
        }

        switch (f->fs.nat_mode) {
        case NAT_MODE_NONE:
                break;
        case NAT_MODE_DIP:
                set_nat_params(adap, f, tid, true, false, false, false);
                break;
        case NAT_MODE_DIP_DP:
                set_nat_params(adap, f, tid, true, false, true, false);
                break;
        case NAT_MODE_DIP_DP_SIP:
                set_nat_params(adap, f, tid, true, true, true, false);
                break;
        case NAT_MODE_DIP_DP_SP:
                set_nat_params(adap, f, tid, true, false, true, true);
                break;
        case NAT_MODE_SIP_SP:
                set_nat_params(adap, f, tid, false, true, false, true);
                break;
        case NAT_MODE_DIP_SIP_SP:
                set_nat_params(adap, f, tid, true, true, false, true);
                break;
        case NAT_MODE_ALL:
                set_nat_params(adap, f, tid, true, true, true, true);
                break;
        default:
                dev_err(adap->pdev_dev, "Invalid NAT mode: %d\n",
                        f->fs.nat_mode);
                cxgb4_filter_hash_delete(f->dev, tid, NULL, GFP_KERNEL);
		cxgb4_hashtid_filter_clear(adap, f);
                if (ctx) {
                        ctx->result = -EINVAL;
                        goto out_complete;
                }
                break;
        }

        if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T7)
                set_tcb_field(adap, f, tid, TCB_T_FLAGS_W,
                              TF_PEND_CTL1_V(1) | TF_PEND_CTL2_V(1),
                              TF_PEND_CTL1_V(f->fs.eport & 0x1) |
                              TF_PEND_CTL2_V((f->fs.eport >> 1) & 0x1), 1);

        if (f->fs.eport >= NUM_UP_TSCH_CHANNEL_INSTANCES)
                set_tcb_tflag(adap, f, tid, TF_RECV_TSTMP_S, 1, 1);

        switch (f->fs.action) {
        case FILTER_PASS:
                if (f->fs.dirsteer)
                        set_tcb_tflag(adap, f, tid, TF_DIRECT_STEER_S, 1, 1);
                break;
        case FILTER_DROP:
                set_tcb_tflag(adap, f, tid, TF_DROP_S, 1, 1);
                break;
        case FILTER_SWITCH:
                set_tcb_tflag(adap, f, tid, TF_LPBK_S, 1, 1);
                break;
        }

        if (is_t5(adap->params.chip) && f->fs.action == FILTER_DROP) {
                /* Set Migrating bit to 1, and
                 * set Non-offload bit to 0 - to achieve
                 * Drop action with Hash filters
                 */
                set_tcb_field(adap, f, tid, TCB_T_FLAGS_W,
                              TF_NON_OFFLOAD_V(1) | TF_MIGRATING_V(1),
                              TF_MIGRATING_V(1), 1);
        }

out_complete:
        if (ctx)
                complete(&ctx->completion);
}

void cxgb4_filter_hash_delete_rpl(struct adapter *adap,
                                  const struct cpl_abort_rpl_rss *rpl)
{
        unsigned int status = rpl->status;
	struct tid_info *t = &adap->tids;
        unsigned int tid = GET_TID(rpl);
        struct filter_ctx *ctx = NULL;
        struct filter_entry *f;

        CH_MSG(adap, INFO, HW,
               "%s: status = %u; tid = %u\n", __func__, status, tid);

	f = lookup_tid(t, tid);
        if (!f) {
                CH_MSG(adap, INFO, HW, "%s:could not find filter entry",
                       __func__);
                return;
        }

        ctx = f->ctx;
        f->ctx = NULL;
        if (ctx) {
                cxgb4_hashtid_filter_clear(adap, f);
                ctx->result = 0;
                complete(&ctx->completion);
        }
}

/* Check a Chelsio Filter Request for validity, convert it into our internal
 * format and send it to the hardware.  Return 0 on success, an error number
 * otherwise.  We attach any provided filter operation context to the internal
 * filter specification in order to facilitate signaling completion of the
 * operation.  The RTNL must be held when calling this function.
 */
int cxgb4_filter_create(struct net_device *dev, u32 filter_id,
                        struct ch_filter_specification *fs,
                        struct filter_ctx *ctx, gfp_t flags)
{
        struct adapter *adap = netdev2adap(dev);
        int ret;

        ret = cxgb4_filter_validate(dev, fs);
        if (ret)
                return ret;

        if (fs->hash) {
                if (is_hashfilter(adap))
                        return cxgb4_filter_hash_create(dev, fs, ctx, flags);

                dev_err(adap->pdev_dev,
                        "Attempt to use maskless filter in non hash-filter configuration; mod-param\n");
                return -EINVAL;
        }

        return cxgb4_filter_normal_create(dev, filter_id, fs, ctx, flags);
}

/* Check a delete filter request for validity and send it to the hardware.
 * Return 0 on success, an error number otherwise.  We attach any provided
 * filter operation context to the internal filter specification in order to
 * facilitate signaling completion of the operation.  The RTNL must be held
 * when calling this function.
 */
int cxgb4_filter_delete(struct net_device *dev, u32 filter_id,
                        struct ch_filter_specification *fs,
                        struct filter_ctx *ctx, gfp_t flags)
{
        struct adapter *adapter = netdev2adap(dev);

        if (fs && fs->hash) {
                if (is_hashfilter(adapter))
                        return cxgb4_filter_hash_delete(dev, filter_id, ctx,
                                                        flags);

                dev_err(adapter->pdev_dev,
                        "Attempt to use maskless filter in non hash-filter configuration; mod-param\n");
                return -EINVAL;
        }

        return cxgb4_filter_normal_delete(dev, filter_id, ctx, flags);
}

void cxgb4_filter_clear_all(struct adapter *adapter)
{
        struct filter_entry *f;
        u8 type, chip_ver;
	u32 srv_idx_reg;
        unsigned int i;

        chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);
	if (adapter->tids.ftid_tab) {
		i = 0;
		while (i < adapter->tids.nhpftids) {
                        type = 0;
			f = &adapter->tids.ftid_tab[i];
			if (f->valid || f->pending) {
                                type = f->fs.type;
				cxgb4_filter_normal_delete(f->dev, f->tid, NULL,
							   GFP_KERNEL);
				cxgb4_ftid_filter_clear(adapter, f);
                        }
			i += type ? 2 : 1;
                }

		while (i < adapter->tids.nftids + adapter->tids.nsftids) {
                        type = 0;
			f = &adapter->tids.ftid_tab[i];
			if (f->valid || f->pending) {
                                type = f->fs.type;
                                cxgb4_filter_normal_delete(f->dev, f->tid, NULL,
                                                           GFP_KERNEL);
				cxgb4_ftid_filter_clear(adapter, f);
			}
			if (type)
				i += chip_ver > CHELSIO_T5 ? 4 : 2;
			else
				i++;
                }
        }

	if (CHELSIO_CHIP_VERSION(adapter->params.chip) <= CHELSIO_T5)
		srv_idx_reg = LE_DB_SERVER_INDEX_A;
	else
		srv_idx_reg = LE_DB_SRVR_START_INDEX_A;
	if (is_hashfilter(adapter) && adapter->tids.tid_tab) {
		unsigned int sb = t4_read_reg(adapter, srv_idx_reg) / 4;

		if (sb) {
			i = 0;
			while (i < sb) {
				type = 0;
				f = adapter->tids.tid_tab[i];
				if (f && (f->valid || f->pending)) {
					type = f->fs.type;
					cxgb4_filter_hash_delete(f->dev, f->tid,
								 NULL,
								 GFP_KERNEL);
					cxgb4_hashtid_filter_clear(adapter, f);
				}
				i += type ? 2 : 1;
                        }

			i = adapter->tids.hash_base;
			while (i < adapter->tids.ntids) {
				type = 0;
				f = adapter->tids.tid_tab[i];
				if (f && (f->valid || f->pending)) {
					type = f->fs.type;
					cxgb4_filter_hash_delete(f->dev, f->tid,
								 NULL,
								 GFP_KERNEL);
					cxgb4_hashtid_filter_clear(adapter, f);
				}
				i += type ? 2 : 1;
                        }

		}
	}
}
EXPORT_SYMBOL(cxgb4_filter_create);

void cxgb4_flush_all_filters(struct adapter *adapter, gfp_t flags)
{
        cxgb4_filter_clear_all(adapter);
}
EXPORT_SYMBOL(cxgb4_flush_all_filters);

/* Retrieve the packet count for the specified filter.
 */
int cxgb4_filter_get_count(struct adapter *adapter, unsigned int fidx,
			   u64 *c, int hash, bool get_byte)
{
        unsigned int tcb_base, tcbaddr;
        struct filter_entry *f;
        int ret;

        tcb_base = t4_read_reg(adapter, TP_CMM_TCB_BASE_A);
        if (is_hashfilter(adapter) && hash) {
		if ((fidx - adapter->tids.tid_base) < adapter->tids.ntids) {
			f = adapter->tids.tid_tab[fidx -
						  adapter->tids.tid_base];
			if (!f)
				return -EINVAL;

			if (is_t5(adapter->params.chip)) {
				*c = get_byte ? f->byte_counter :
						f->pkt_counter;
				return 0;
			}

			tcbaddr = tcb_base + (fidx * TCB_SIZE);
			goto get_count;
		} else {
			return -E2BIG;
                }
        } else {
		if ((fidx != (adapter->tids.nftids + adapter->tids.nsftids +
			      adapter->tids.nhpftids - 1)) &&
		    (fidx >= adapter->tids.nftids + adapter->tids.nhpftids))
			return -E2BIG;

		f = &adapter->tids.ftid_tab[fidx];
		if (!f->valid)
			return -EINVAL;

		tcbaddr = tcb_base + f->tid * TCB_SIZE;
        }

	f = &adapter->tids.ftid_tab[fidx];
        if (!f->valid)
                return -EINVAL;

get_count:
        if (is_t4(adapter->params.chip)) {
                /* For T4, the Filter Packet Hit Count is maintained as a
                 * 64-bit Big Endian value in the TCB fields
                 * {t_rtt_ts_recent_age, t_rtseq_recent} ...  For insanely
                 * crazy (and completely unknown) reasons, the format in
                 * memory is swizzled/mapped in a manner such that instead
                 * of having this 64-bit counter show up at offset 24
                 * ((TCB_T_RTT_TS_RECENT_AGE_W == 6) * sizeof(u32)), it
                 * actually shows up at offset 16.  After more than an hour
                 * trying to untangle things so it could be properly coded
                 * and documented here, it's simply not worth the effort.
                 * So we use an incredibly gross "4" constant instead of
                 * TCB_T_RTT_TS_RECENT_AGE_W.
                 */
                if (get_byte) {
                        unsigned int word_offset = 4;
                        __be64 be64_byte_count;

                        spin_lock(&adapter->win0_lock);
                        ret = t4_memory_rw(adapter, MEMWIN_NIC, MEM_EDC0,
                                           tcbaddr + (word_offset * sizeof(__be32)),
                                           sizeof(be64_byte_count), &be64_byte_count,
                                           T4_MEMORY_READ);
                        spin_unlock(&adapter->win0_lock);
                        if (ret < 0)
                                return ret;
                        *c = be64_to_cpu(be64_byte_count);
                } else {
                        unsigned int word_offset = 4;
                        __be64 be64_count;

                        spin_lock(&adapter->win0_lock);
                        ret = t4_memory_rw(adapter, MEMWIN_NIC, MEM_EDC0,
                                           tcbaddr + (word_offset * sizeof(__be32)),
                                           sizeof(be64_count), (__be32 *)&be64_count,
                                           T4_MEMORY_READ);
                        spin_unlock(&adapter->win0_lock);
                        if (ret < 0)
                                return ret;
                        *c = be64_to_cpu(be64_count);
                }
        } else {
                /* For T5, the Filter Packet Hit Count is maintained as a
                 * 32-bit Big Endian value in the TCB field {timestamp}.
                 * Similar to the craziness above, instead of the filter hit
                 * count showing up at offset 20 ((TCB_TIMESTAMP_W == 5) *
                 * sizeof(u32)), it actually shows up at offset 24.  Whacky.
                 */
                if (get_byte) {
                        unsigned int word_offset = 4;
                        __be64 be64_byte_count;

                        spin_lock(&adapter->win0_lock);
                        ret = t4_memory_rw(adapter, MEMWIN_NIC, MEM_EDC0,
                                           tcbaddr + (word_offset * sizeof(__be32)),
                                           sizeof(be64_byte_count), &be64_byte_count,
                                           T4_MEMORY_READ);
                        spin_unlock(&adapter->win0_lock);
                        if (ret < 0)
                                return ret;
                        *c = be64_to_cpu(be64_byte_count);
                } else {
                        unsigned int word_offset = 6;
                        __be32 be32_count;

                        spin_lock(&adapter->win0_lock);
                        ret = t4_memory_rw(adapter, MEMWIN_NIC, MEM_EDC0,
                                           tcbaddr + (word_offset * sizeof(__be32)),
                                           sizeof(be32_count), &be32_count,
                                           T4_MEMORY_READ);
                        spin_unlock(&adapter->win0_lock);
                        if (ret < 0)
                                return ret;
                        *c = (u64)be32_to_cpu(be32_count);
                }
        }

        return 0;
}
EXPORT_SYMBOL(cxgb4_filter_delete);

int cxgb4_filter_get_counters(struct net_device *dev, unsigned int fidx,
                              u64 *hitcnt, u64 *bytecnt, int hash)
{
        struct adapter *adapter = netdev2adap(dev);
        int ret;

        ret = cxgb4_filter_get_count(adapter, fidx, hitcnt, hash, false);
        if (ret < 0)
                return ret;

        return cxgb4_filter_get_count(adapter, fidx, bytecnt, hash, true);
}
EXPORT_SYMBOL(cxgb4_filter_get_counters);

static bool cxgb4_filter_prio_in_range(struct tid_info *t, u32 idx, u8 nslots,
		u32 prio)
{
	struct filter_entry *prev_tab, *next_tab, *prev_fe, *next_fe;
	u32 prev_ftid, next_ftid;

	/* Only insert the rule if both of the following conditions
	 * are met:
	 * 1. The immediate previous rule has priority <= @prio.
	 * 2. The immediate next rule has priority >= @prio.
	 */

	/* High Priority (HPFILTER) region always has higher priority
	 * than normal FILTER region. So, all rules in HPFILTER region
	 * must have prio value <= rules in normal FILTER region.
	 */
	if (idx < t->nhpftids) {
		/* Don't insert if there's a rule already present at @idx
		 * in HPFILTER region.
		 */
		if (test_bit(idx, t->hpftid_bmap))
			return false;

		next_tab = t->hpftid_tab;
		next_ftid = find_next_bit(t->hpftid_bmap, t->nhpftids, idx);
		if (next_ftid >= t->nhpftids) {
			/* No next entry found in HPFILTER region.
			 * See if there's any next entry in normal
			 * FILTER region.
			 */
			next_ftid = find_first_bit(t->ftid_bmap, t->nftids);
			if (next_ftid >= t->nftids)
				next_ftid = idx;
			else
				next_tab = t->ftid_tab;
		}

		/* Search for the closest previous filter entry in HPFILTER
		 * region. No need to search in normal FILTER region because
		 * there can never be any entry in normal FILTER region whose
		 * prio value is < last entry in HPFILTER region.
		 */
		prev_ftid = find_last_bit(t->hpftid_bmap, idx);
		if (prev_ftid >= idx)
			prev_ftid = idx;

		prev_tab = t->hpftid_tab;
	} else {
		idx -= t->nhpftids;

		/* Don't insert if there's a rule already present at @idx
		 * in normal FILTER region.
		 */
		if (test_bit(idx, t->ftid_bmap))
			return false;

		prev_tab = t->ftid_tab;
		prev_ftid = find_last_bit(t->ftid_bmap, idx);
		if (prev_ftid >= idx) {
			/* No previous entry found in normal FILTER
			 * region. See if there's any previous entry
			 * in HPFILTER region.
			 */
			prev_ftid = find_last_bit(t->hpftid_bmap, t->nhpftids);
			if (prev_ftid >= t->nhpftids)
				prev_ftid = idx;
			else
				prev_tab = t->hpftid_tab;
		}

		/* Search for the closest next filter entry in normal
		 * FILTER region. No need to search in HPFILTER region
		 * because there can never be any entry in HPFILTER
		 * region whose prio value is > first entry in normal
		 * FILTER region.
		 */
		next_ftid = find_next_bit(t->ftid_bmap, t->nftids, idx);
		if (next_ftid >= t->nftids)
			next_ftid = idx;

		next_tab = t->ftid_tab;
	}

	next_fe = &next_tab[next_ftid];

	/* See if the filter entry belongs to an IPv6 rule, which
	 * occupy 4 slots on T5 and 2 slots on T6. Adjust the
	 * reference to the previously inserted filter entry
	 * accordingly.
	 */
	prev_fe = &prev_tab[prev_ftid & ~(nslots - 1)];
	if (!prev_fe->fs.type)
		prev_fe = &prev_tab[prev_ftid];

	if ((prev_fe->valid && prev_fe->fs.tc_prio > prio) ||
			(next_fe->valid && next_fe->fs.tc_prio < prio))
		return false;

	return true;
}

int cxgb4_get_free_ftid(struct net_device *dev, u8 family, bool hash_en,
			u32 tc_prio)
{
	struct adapter *adap = netdev2adap(dev);
	struct tid_info *t = &adap->tids;
	u32 bmap_ftid, max_ftid;
	struct filter_entry *f;
	unsigned long *bmap;
	bool found = false;
	u8 i, cnt, n;
	int ftid = 0;

	/* IPv4 occupy 1 slot. IPv6 occupy 2 slots on T6 and 4 slots
	 * on T5.
	 */
	n = 1;
	if (family == PF_INET6) {
		n++;
		if (CHELSIO_CHIP_VERSION(adap->params.chip) < CHELSIO_T6)
			n += 2;
	}

	/* There are 3 filter regions available in hardware in
	 * following order of priority:
	 *
	 * 1. High Priority (HPFILTER) region (Highest Priority).
	 * 2. HASH region.
	 * 3. Normal FILTER region (Lowest Priority).
	 *
	 * Entries in HPFILTER and normal FILTER region have index
	 * 0 as the highest priority and the rules will be scanned
	 * in ascending order until either a rule hits or end of
	 * the region is reached.
	 *
	 * All HASH region entries have same priority. The set of
	 * fields to match in headers are pre-determined. The same
	 * set of header match fields must be compulsorily specified
	 * in all the rules wanting to get inserted in HASH region.
	 * Hence, HASH region is an exact-match region. A HASH is
	 * generated for a rule based on the values in the
	 * pre-determined set of header match fields. The generated
	 * HASH serves as an index into the HASH region. There can
	 * never be 2 rules having the same HASH. Hardware will
	 * compute a HASH for every incoming packet based on the
	 * values in the pre-determined set of header match fields
	 * and uses it as an index to check if there's a rule
	 * inserted in the HASH region at the specified index. If
	 * there's a rule inserted, then it's considered as a filter
	 * hit. Otherwise, it's a filter miss and normal FILTER region
	 * is scanned afterwards.
	 */

	spin_lock_bh(&t->ftid_lock);

	ftid = (tc_prio <= t->nhpftids) ? 0 : t->nhpftids;
	max_ftid = t->nftids + t->nhpftids;
	while (ftid < max_ftid) {
		if (ftid < t->nhpftids) {
			/* If the new rule wants to get inserted into
			 * HPFILTER region, but its prio is greater
			 * than the rule with the highest prio in HASH
			 * region, or if there's not enough slots
			 * available in HPFILTER region, then skip
			 * trying to insert this rule into HPFILTER
			 * region and directly go to the next region.
			 */
			if ((t->tc_hash_tids_max_prio &&
						tc_prio > t->tc_hash_tids_max_prio) ||
					(ftid + n) > t->nhpftids) {
				ftid = t->nhpftids;
				continue;
			}

			bmap = t->hpftid_bmap;
			bmap_ftid = ftid;
		} else if (hash_en) {
			/* Ensure priority is >= last rule in HPFILTER
			 * region.
			 */
			ftid = find_last_bit(t->hpftid_bmap, t->nhpftids);
			if (ftid < t->nhpftids) {
				f = &t->hpftid_tab[ftid];
				if (f->valid && tc_prio < f->fs.tc_prio)
					break;
			}

			/* Ensure priority is <= first rule in normal
			 * FILTER region.
			 */
			ftid = find_first_bit(t->ftid_bmap, t->nftids);
			if (ftid < t->nftids) {
				f = &t->ftid_tab[ftid];
				if (f->valid && tc_prio > f->fs.tc_prio)
					break;
			}

			found = true;
			ftid = t->nhpftids;
			goto out_unlock;
		} else {
			/* If the new rule wants to get inserted into
			 * normal FILTER region, but its prio is less
			 * than the rule with the highest prio in HASH
			 * region, then reject the rule.
			 */
			if (t->tc_hash_tids_max_prio &&
					tc_prio < t->tc_hash_tids_max_prio)
				break;

			if (ftid + n > max_ftid)
				break;

			bmap = t->ftid_bmap;
			bmap_ftid = ftid - t->nhpftids;
		}

		cnt = 0;
		for (i = 0; i < n; i++) {
			if (test_bit(bmap_ftid + i, bmap))
				break;
			cnt++;
		}

		if (cnt == n) {
			/* Ensure the new rule's prio doesn't conflict
			 * with existing rules.
			 */
			if (cxgb4_filter_prio_in_range(t, ftid, n,
						tc_prio)) {
				ftid &= ~(n - 1);
				found = true;
				break;
			}
		}

		ftid += n;
	}

out_unlock:
	spin_unlock_bh(&t->ftid_lock);
	return found ? ftid : -ENOMEM;
}

int cxgb4_hash_filter_config_verify(struct adapter *adap, bool offload_caps)
{
        u32 val;

        if (CHELSIO_CHIP_VERSION(adap->params.chip) < CHELSIO_T5)
                return 0;

        if (CHELSIO_CHIP_VERSION(adap->params.chip) == CHELSIO_T5) {
                if (offload_caps)
                        return -EOPNOTSUPP;

                return 0;
        }

        /* On T6+, if hash filter is enabled with or without ofld enabled, verify
         * necessary register configs and warn the user in case of improper
         * config.
         */
        if (offload_caps) {
                val = t4_read_reg(adap, TP_GLOBAL_CONFIG_A);
                if (!(val & ACTIVEFILTERCOUNTS_F)) {
                        dev_warn(adap->pdev_dev,
                                 "Invalid hash filter + ofld config: reg[0x%x] = 0x%x\n",
                                 TP_GLOBAL_CONFIG_A, val);
                        return -EOPNOTSUPP;
                }
        } else {
                val = t4_read_reg(adap, LE_DB_RSP_CODE_0_A);
                if (TCAM_ACTV_HIT_G(val) != 4) {
                        dev_warn(adap->pdev_dev,
                                 "Invalid hash filter config: [0x%x]=0x%x\n",
                                 LE_DB_RSP_CODE_0_A, val);
                        return -EOPNOTSUPP;
                }

                val = t4_read_reg(adap, LE_DB_RSP_CODE_1_A);
                if (HASH_ACTV_HIT_G(val) != 4) {
                        dev_warn(adap->pdev_dev,
                                 "Invalid hash filter config: [0x%x]=0x%x\n",
                                 LE_DB_RSP_CODE_1_A, val);
                        return -EOPNOTSUPP;
                }
        }

        return 0;
}
#if 0
// __SS__ commenting for now
int cxgb4_hash_filter_init(struct adapter *adap)
{
	unsigned int user_filter_perc;
	unsigned int n_user_filters;
	u32 params[7], val[7];
	unsigned int chip_ver;
	int ret;

	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

	/* On T6+, if hash filter is enabled with or without ofld enabled, verify
	 * necessary register configs and warn the user in case of improper
	 * config.
	 */
	if (chip_ver >= CHELSIO_T6) {
		if (is_offload(adap)) {
			if (!(t4_read_reg(adap, TP_GLOBAL_CONFIG_A)
			    & ACTIVEFILTERCOUNTS_F))
				pr_warn("%s: Invalid hash filter + ofld config",
					__func__);
		} else {
			if (TCAM_ACTV_HIT_G(
				t4_read_reg(adap, LE_DB_RSP_CODE_0_A)) != 4)
				pr_warn("%s: Invalid hash filter config\n",
					__func__);

			if (HASH_ACTV_HIT_G(
				t4_read_reg(adap, LE_DB_RSP_CODE_1_A)) != 4)
				pr_warn("%s: Invalid hash filter config\n",
					__func__);
		}
	}

#define MAX_ATIDS 8192U

	params[0] = FW_PARAM_DEV(NTID);
	params[1] = FW_PARAM_PFVF(SERVER_START);
	params[2] = FW_PARAM_PFVF(SERVER_END);
	params[3] = FW_PARAM_PFVF(TDDP_START);
	params[4] = FW_PARAM_PFVF(TDDP_END);
	params[5] = FW_PARAM_DEV(FLOWC_BUFFIFO_SZ);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 6,
			      params, val);
	if (ret < 0)
		return ret;
	adap->tids.ntids = val[0];
	adap->tids.natids = min(adap->tids.ntids / 2, MAX_ATIDS);
	adap->tids.stid_base = val[1];
	adap->tids.nstids = val[2] - val[1] + 1;

	user_filter_perc = 100;
	n_user_filters = mult_frac(adap->tids.nftids,
				   user_filter_perc,
				   100);
	adap->tids.sftid_base = adap->tids.ftid_base + n_user_filters;
	adap->tids.nsftids = adap->tids.nftids - n_user_filters;
	adap->tids.nftids = adap->tids.sftid_base -
			     adap->tids.ftid_base;

        adap->params.hash_filter = 1;
        return 0;
}
#endif

int cxgb4_create_server_filter(const struct net_device *dev, unsigned int stid,
			       __be32 sip, __be16 sport, __be16 vlan,
			       unsigned int queue, unsigned char port,
			       unsigned char mask)
{
        struct filter_entry *f;
	struct adapter *adap;
        int i, ret;
        u8 *val;

	adap = netdev2adap(dev);

	/* Adjust stid to correct filter index */
	stid -= adap->tids.sftid_base;
	stid += adap->tids.nftids;

	/* Check to make sure the filter requested is writable ...
	 */
	f = &adap->tids.ftid_tab[stid];
	ret = cxgb4_filter_writable(f);
        if (ret)
		return ret;

	if (f->valid)
		return -EBUSY;

	/* Clear out filter specifications */
	memset(&f->fs, 0, sizeof(struct ch_filter_specification));
	f->fs.val.lport = cpu_to_be16(sport);
	f->fs.mask.lport = ~0;
        val = (u8 *)&sip;
        if ((val[0] | val[1] | val[2] | val[3]) != 0) {
                for (i = 0; i < 4; i++) {
                        f->fs.val.lip[i] = val[i];
                        f->fs.mask.lip[i] = ~0;
                }
                if (adap->params.tp.vlan_pri_map & PORT_F) {
                        f->fs.val.iport = port;
                        f->fs.mask.iport = mask;
                }
        }

        if (adap->params.tp.vlan_pri_map & PROTOCOL_F) {
                f->fs.val.proto = IPPROTO_TCP;
                f->fs.mask.proto = ~0;
        }

        /* This code demonstrates how one would selectively Offload
         * (TOE) certain incoming connections by using the extended
         * "Filter Information" capabilities of Server Control Blocks
         * (SCB).  (See "Classification and Filtering" in the T4 Data
         * Book for a description of Ingress Packet pattern matching
         * capabilities.  See also documentation on the
         * TP_VLAN_PRI_MAP register.)  Because this selective
         * Offloading is happening in the chip, this allows
         * non-Offloading and Offloading drivers to coexist.  For
         * example, an Offloading Driver might be running in a
         * Hypervisor while non-Offloading vNIC Drivers might be
         * running in Virtual Machines.
         *
         * This particular example code demonstrates how one would
         * selectively Offload incoming connections based on VLANs.
         * We allow one VLAN to be designated as the "Offloading
         * VLAN".  Ingress SYNs on this Offload VLAN will match the
         * filter which we put into the Listen SCB and will result in
         * Offloaded Connections on that VLAN.  Incoming SYNs on other
         * VLANs will not match and will go through normal NIC
         * processing.
         *
         * This is not production code since one would want a lot more
         * infrastructure to allow a variety of filter specifications
         * on a per-server basis.  But this demonstrates the
         * fundamental mechanisms one would use to build such an
         * infrastructure.
         */
        if (vlan && (adap->params.tp.vlan_pri_map & VLAN_F)) {
                f->fs.val.ivlan_vld = 1;
                f->fs.val.ivlan = be16_to_cpu(vlan);
                f->fs.mask.ivlan_vld = ~0;
                f->fs.mask.ivlan = ~0;
        }

        f->fs.dirsteer = 1;
        f->fs.iq = queue;
        /* Mark filter as locked */
        f->locked = 1;
        f->fs.rpttid = 1;

        /* Save the actual tid. We need this to get the corresponding
         * filter entry structure in filter_rpl.
         */
	f->tid = stid + adap->tids.ftid_base;
	ret = cxgb4_filter_normal_create_wr(adap, stid, GFP_KERNEL);
	if (ret) {
		cxgb4_filter_clear(adap, f);
		return ret;
	}

        return 0;
}
EXPORT_SYMBOL(cxgb4_create_server_filter);

int cxgb4_remove_server_filter(const struct net_device *dev, unsigned int stid,
			       unsigned int queue, bool ipv6)
{
        struct filter_entry *f;
	struct adapter *adap;
        int ret;

	adap = netdev2adap(dev);

	/* Adjust stid to correct filter index */
	stid -= adap->tids.sftid_base;
	stid += adap->tids.nftids;

	f = &adap->tids.ftid_tab[stid];
        /* Unlock the filter */
        f->locked = 0;

	ret = cxgb4_filter_normal_delete_wr(adap, stid, GFP_KERNEL);
	if (ret)
		return ret;

	return 0;
}
EXPORT_SYMBOL(cxgb4_remove_server_filter);

//----------------- END old filter changes -----------------------------

/* Filter Table Debugfs.
 */
static void cxgb4_filter_debugfs_show_field_name(struct seq_file *seq,
                                                 u32 chip_ver, u8 offset,
                                                 u32 fconf, u32 tpiconf)
{
        if (chip_ver >= CHELSIO_T7) {
                switch (fconf & (1 << offset)) {
                case 0:
                        /* Compressed filter field not enabled */
                        break;
                case IPSECIDX_F:
                        seq_puts(seq, " IPSecIdx");
                        break;
                case T7_FCOE_F:
                        seq_puts(seq, " FCoE");
                        break;
                case T7_PORT_F:
                        seq_puts(seq, " Port");
                        break;
                case T7_VNIC_ID_F:
                        if (tpiconf & USE_ENC_IDX_F)
                                seq_puts(seq, "    vld:MPS:Id");
                        else if(tpiconf & VNIC_F)
                                seq_puts(seq, "   VFvld:PF:VF");
                        else
                                seq_puts(seq, "     vld:oVLAN");
                        break;
                case T7_VLAN_F:
                        seq_puts(seq, "     vld:iVLAN");
                        break;
                case T7_TOS_F:
                        seq_puts(seq, "   TOS");
                        break;
                case T7_PROTOCOL_F:
                        seq_puts(seq, "  Prot");
                        break;
                case T7_ETHERTYPE_F:
                        seq_puts(seq, "   EthType");
                        break;
                case T7_MACMATCH_F:
                        seq_puts(seq, "  MACIdx");
                        break;
                case T7_MPSHITTYPE_F:
                        seq_puts(seq, " MPS");
                        break;
                case T7_FRAGMENTATION_F:
                        seq_puts(seq, " Frag");
                        break;
                case ROCE_F:
                        seq_puts(seq, " RoCE");
                        break;
                case SYNONLY_F:
                        seq_puts(seq, " SYN");
                        break;
                case TCPFLAGS_F:
                        seq_puts(seq, " TCPFlags");
                        break;
                }

                return;
        }

        switch (fconf & (1 << offset)) {
        case 0:
                /* Compressed filter field not enabled */
                break;
        case FCOE_F:
                seq_puts(seq, " FCoE");
                break;
        case PORT_F:
                seq_puts(seq, " Port");
                break;
        case VNIC_ID_F:
                if (tpiconf & USE_ENC_IDX_F)
                        seq_puts(seq, "    vld:MPS:Id");
                else if(tpiconf & VNIC_F)
                        seq_puts(seq, "   VFvld:PF:VF");
                else
                        seq_puts(seq, "     vld:oVLAN");
                break;
        case VLAN_F:
                seq_puts(seq, "     vld:iVLAN");
                break;
        case TOS_F:
                seq_puts(seq, "   TOS");
                break;
        case PROTOCOL_F:
                seq_puts(seq, "  Prot");
                break;
        case ETHERTYPE_F:
                seq_puts(seq, "   EthType");
                break;
        case MACMATCH_F:
                seq_puts(seq, "  MACIdx");
                break;
        case MPSHITTYPE_F:
                seq_puts(seq, " MPS");
                break;
        case FRAGMENTATION_F:
                seq_puts(seq, " Frag");
                break;
        }
}

static void cxgb4_filter_debugfs_show_field_data(struct seq_file *seq,
                                                 u32 chip_ver, u8 offset,
                                                 u32 fconf, u32 tpiconf,
                                                 struct filter_entry *f)
{
        if (chip_ver >= CHELSIO_T7) {
                switch (fconf & (1 << offset)) {
                case 0:
                        /* Compressed filter field not enabled */
                        break;
                case IPSECIDX_F:
                        seq_printf(seq, "  %04x/%04x", f->fs.val.ipsecidx,
                                   f->fs.mask.ipsecidx);
                        break;
                case T7_FCOE_F:
                        seq_printf(seq, "  %1d/%1d", f->fs.val.fcoe,
                                   f->fs.mask.fcoe);
                        break;
                case T7_PORT_F:
                        seq_printf(seq, "  %1d/%1d", f->fs.val.iport,
                                   f->fs.mask.iport);
                        break;
                case T7_VNIC_ID_F:
                        if (tpiconf & USE_ENC_IDX_F)
                                seq_printf(seq, " %1d:%1x:%02x/%1d:%1x:%02x",
                                           f->fs.val.ovlan_vld,
                                           (f->fs.val.ovlan >> 9) & 0x7,
                                           f->fs.val.ovlan & 0x1ff,
                                           f->fs.mask.ovlan_vld,
                                           (f->fs.mask.ovlan >> 9) & 0x7,
                                           f->fs.mask.ovlan & 0x1ff);
                        else if (tpiconf & VNIC_F)
                                seq_printf(seq, " %1d:%1x:%02x/%1d:%1x:%02x",
                                           f->fs.val.ovlan_vld,
                                           (f->fs.val.ovlan >> 13) & 0x7,
                                           f->fs.val.ovlan & 0x7f,
                                           f->fs.mask.ovlan_vld,
                                           (f->fs.mask.ovlan >> 13) & 0x7,
                                           f->fs.mask.ovlan & 0x7f);
                        else
                                seq_printf(seq, " %1d:%04x/%1d:%04x",
                                           f->fs.val.ovlan_vld,
                                           f->fs.val.ovlan,
                                           f->fs.mask.ovlan_vld,
                                           f->fs.mask.ovlan);
                        break;
                case T7_VLAN_F:
                        seq_printf(seq, " %1d:%04x/%1d:%04x",
                                   f->fs.val.ivlan_vld,
                                   f->fs.val.ivlan,
                                   f->fs.mask.ivlan_vld,
                                   f->fs.mask.ivlan);
                        break;
                case T7_TOS_F:
                        seq_printf(seq, " %02x/%02x", f->fs.val.tos,
                                   f->fs.mask.tos);
                        break;
                case T7_PROTOCOL_F:
                        seq_printf(seq, " %02x/%02x", f->fs.val.proto,
                                   f->fs.mask.proto);
                        break;
                case T7_ETHERTYPE_F:
                        seq_printf(seq, " %04x/%04x", f->fs.val.ethtype,
                                   f->fs.mask.ethtype);
                        break;
                case T7_MACMATCH_F:
                        seq_printf(seq, " %03x/%03x", f->fs.val.macidx,
                                   f->fs.mask.macidx);
                        break;
                case T7_MPSHITTYPE_F:
                        seq_printf(seq, " %1x/%1x", f->fs.val.matchtype,
                                   f->fs.mask.matchtype);
                        break;
                case T7_FRAGMENTATION_F:
                        seq_printf(seq, "  %1d/%1d", f->fs.val.frag,
                                   f->fs.mask.frag);
                        break;
                case ROCE_F:
                        seq_printf(seq, "  %1d/%1d", f->fs.val.roce,
                                   f->fs.mask.roce);
                        break;
                case SYNONLY_F:
                        seq_printf(seq, "  %1d/%1d", f->fs.val.synonly,
                                   f->fs.mask.synonly);
                        break;
                case TCPFLAGS_F:
                        seq_printf(seq, "  %04x/%04x", f->fs.val.tcpflags,
                                   f->fs.mask.tcpflags);
                        break;
                }

                return;
        }

        switch (fconf & (1 << offset)) {
        case 0:
                /* Compressed filter field not enabled */
                break;
        case FCOE_F:
                seq_printf(seq, "  %1d/%1d", f->fs.val.fcoe, f->fs.mask.fcoe);
                break;
        case PORT_F:
                seq_printf(seq, "  %1d/%1d", f->fs.val.iport, f->fs.mask.iport);
                break;
        case VNIC_ID_F:
                if (tpiconf & USE_ENC_IDX_F)
                        seq_printf(seq, " %1d:%1x:%02x/%1d:%1x:%02x",
                                   f->fs.val.ovlan_vld,
                                   (f->fs.val.ovlan >> 9) & 0x7,
                                   f->fs.val.ovlan & 0x1ff,
                                   f->fs.mask.ovlan_vld,
                                   (f->fs.mask.ovlan >> 9) & 0x7,
                                   f->fs.mask.ovlan & 0x1ff);
                else if (tpiconf & VNIC_F)
                        seq_printf(seq, " %1d:%1x:%02x/%1d:%1x:%02x",
                                   f->fs.val.ovlan_vld,
                                   (f->fs.val.ovlan >> 13) & 0x7,
                                   f->fs.val.ovlan & 0x7f,
                                   f->fs.mask.ovlan_vld,
                                   (f->fs.mask.ovlan >> 13) & 0x7,
                                   f->fs.mask.ovlan & 0x7f);
                else
                        seq_printf(seq, " %1d:%04x/%1d:%04x",
                                   f->fs.val.ovlan_vld,
                                   f->fs.val.ovlan,
                                   f->fs.mask.ovlan_vld,
                                   f->fs.mask.ovlan);
                break;
        case VLAN_F:
                seq_printf(seq, " %1d:%04x/%1d:%04x",
                           f->fs.val.ivlan_vld,
                           f->fs.val.ivlan,
                           f->fs.mask.ivlan_vld,
                           f->fs.mask.ivlan);
                break;
        case TOS_F:
                seq_printf(seq, " %02x/%02x", f->fs.val.tos, f->fs.mask.tos);
                break;
        case PROTOCOL_F:
                seq_printf(seq, " %02x/%02x", f->fs.val.proto,
                           f->fs.mask.proto);
                break;
        case ETHERTYPE_F:
                seq_printf(seq, " %04x/%04x", f->fs.val.ethtype,
                           f->fs.mask.ethtype);
                break;
        case MACMATCH_F:
                seq_printf(seq, " %03x/%03x", f->fs.val.macidx,
                           f->fs.mask.macidx);
                break;
        case MPSHITTYPE_F:
                seq_printf(seq, " %1x/%1x", f->fs.val.matchtype,
                           f->fs.mask.matchtype);
                break;
        case FRAGMENTATION_F:
                seq_printf(seq, "  %1d/%1d", f->fs.val.frag, f->fs.mask.frag);
                break;
        }
}

static void cxgb4_filter_debugfs_show_ipaddr(struct seq_file *seq,
                                             int type, u8 *addr, u8 *addrm)
{
        int noctets, octet;

        seq_puts(seq, " ");
        if (type == 0) {
                noctets = 4;
                seq_printf(seq, "%48s", " ");
        } else
                noctets = 16;

        for (octet = 0; octet < noctets; octet++)
                seq_printf(seq, "%02x", addr[octet]);
        seq_puts(seq, "/");
        for (octet = 0; octet < noctets; octet++)
                seq_printf(seq, "%02x", addrm[octet]);
}

static void cxgb4_filter_debugfs_display(struct seq_file *seq, u32 fidx,
                                         struct filter_entry *f, int hash)
{
        struct adapter *adap = seq->private;
        u32 fconf, tpiconf, chip_ver;
        u8 first, last;
        int i;

        fconf = adap->params.tp.vlan_pri_map;
        tpiconf = adap->params.tp.ingress_config;
        chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
        if (chip_ver >= CHELSIO_T7) {
                first = T7_FT_FIRST_S;
                last = T7_FT_LAST_S;
        } else {
                first = FT_FIRST_S;
                last = FT_LAST_S;
        }

        /* Filter index. */
        /* T7: for both ipv4 and ipv6, the hash tid is only one, So fall to ipv4 print here */
        if (f->fs.type && !(hash && chip_ver >= CHELSIO_T7))
                seq_printf(seq, "%4d ..%4d%c%c", fidx,
                           chip_ver < CHELSIO_T6 ? fidx+3 : fidx+1,
                           (!f->locked  ? ' ' : '!'),
                           (!f->pending ? ' ' : (!f->valid ? '+' : '-')));
        else
                seq_printf(seq, "%4d       %c%c", fidx,
                           (!f->locked  ? ' ' : '!'),
                           (!f->pending ? ' ' : (!f->valid ? '+' : '-')));

        if (f->fs.hitcnts) {
                u64 hitcnt;
                int ret;

		ret = cxgb4_filter_get_count(adap, fidx, &hitcnt, hash, false);
                if (ret)
                        seq_printf(seq, " %20s", "hits={ERROR}");
                else
                        seq_printf(seq, " %20llu", hitcnt);

		ret = cxgb4_filter_get_count(adap, fidx, &hitcnt, hash, true);
                if (ret)
                        seq_printf(seq, " %20s", "bytes={ERROR}");
                else
                        seq_printf(seq, " %20llu", hitcnt);
        } else {
                seq_printf(seq, " %20s", "Disabled");
                seq_printf(seq, " %20s", "Disabled");
        }

        /* Compressed header portion of filter. */
        for (i = first; i <= last; i++)
                cxgb4_filter_debugfs_show_field_data(seq, chip_ver, i, fconf,
                                                     tpiconf, f);

        /* Fixed portion of filter. */
        cxgb4_filter_debugfs_show_ipaddr(seq, f->fs.type, f->fs.val.lip,
                                         f->fs.mask.lip);
        cxgb4_filter_debugfs_show_ipaddr(seq, f->fs.type, f->fs.val.fip,
                                         f->fs.mask.fip);
        seq_printf(seq, " %04x/%04x %04x/%04x",
                   f->fs.val.lport, f->fs.mask.lport,
                   f->fs.val.fport, f->fs.mask.fport);

        /* Variable length filter action. */
        if (f->fs.action == FILTER_DROP)
                seq_puts(seq, " Drop");
        else if (f->fs.action == FILTER_SWITCH) {
                seq_printf(seq, " Switch: port=%d", f->fs.eport);
                if (f->fs.newdmac)
                        seq_printf(seq,
                                   ", dmac=%02x:%02x:%02x:%02x:%02x:%02x"
                                   ", l2tidx=%d",
                                   f->fs.dmac[0], f->fs.dmac[1],
                                   f->fs.dmac[2], f->fs.dmac[3],
                                   f->fs.dmac[4], f->fs.dmac[5],
                                   f->l2t->idx);
                if (f->fs.newsmac)
                        seq_printf(seq,
                                   ", smac=%02x:%02x:%02x:%02x:%02x:%02x"
                                   ", smtidx=%d",
                                   f->fs.smac[0], f->fs.smac[1],
                                   f->fs.smac[2], f->fs.smac[3],
                                   f->fs.smac[4], f->fs.smac[5],
                                   f->smtidx);
                if (f->fs.newvlan == VLAN_REMOVE)
                        seq_printf(seq, ", vlan=none");
                else if (f->fs.newvlan == VLAN_INSERT)
                        seq_printf(seq, ", vlan=insert(%x)",
                                        f->fs.vlan);
                else if (f->fs.newvlan == VLAN_REWRITE)
                        seq_printf(seq, ", vlan=rewrite(%x)",
                                        f->fs.vlan);
        } else {
                seq_puts(seq, " Pass: Q=");
                if (f->fs.dirsteer == 0) {
                        seq_puts(seq, "RSS");
                        if (f->fs.maskhash)
                                seq_puts(seq, "(TCB=hash)");
                } else {
                        seq_printf(seq, "%d", f->fs.iq);
                        if (f->fs.dirsteerhash == 0)
                                seq_puts(seq, "(QID)");
                        else
                                seq_puts(seq, "(hash)");
                }
        }
        if (f->fs.prio)
                seq_puts(seq, " Prio");
        if (f->fs.rpttid)
                seq_puts(seq, " RptTID");
        seq_puts(seq, "\n");
}

static int cxgb4_filter_normal_debugfs_show(struct seq_file *seq, void *v)
{
	struct adapter *adap = seq->private;
	u32 fconf, tpiconf, chip_ver;
	struct cxgb4_tid_info *t;
	u8 first, last;
	int i;

	fconf = adap->params.tp.vlan_pri_map;
	tpiconf = adap->params.tp.ingress_config;
	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
	if (chip_ver >= CHELSIO_T7) {
		first = T7_FT_FIRST_S;
		last = T7_FT_LAST_S;
	} else {
		first = FT_FIRST_S;
		last = FT_LAST_S;
	}

	t = &adap->tidinfo;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "[[Legend: "
				"'!' => locked; "
				"'+' => pending set; "
				"'-' => pending clear]]\n");
		seq_puts(seq, " Idx                          Hits");
		seq_puts(seq, "            Hit-Bytes");
		for (i = first; i <= last; i++)
			cxgb4_filter_debugfs_show_field_name(seq, chip_ver,
					i, fconf, tpiconf);
		seq_printf(seq, " %65s %65s %9s %9s %s\n",
				"LIP", "FIP", "LPORT", "FPORT", "Action");
	} else {
		int fidx = (uintptr_t)v - 2;
		struct filter_entry *f = &adap->tids.ftid_tab[fidx];

		/* If this entry isn't filled in just return */
		if (!f->valid && !f->pending)
			return 0;

		cxgb4_filter_debugfs_display(seq, fidx, f, 0);
	}
	return 0;
}

static inline void *filters_get_idx(struct adapter *adap, loff_t pos)
{
	if (pos > (adap->tids.nftids + adap->tids.nsftids +
		   adap->tids.nhpftids))
		return NULL;

	return (void *)(uintptr_t)(pos + 1);
}

#if 0
static void *filters_start(struct seq_file *seq, loff_t *pos)
{
	struct adapter *adap = seq->private;

	return *pos ? filters_get_idx(adap, *pos) : SEQ_START_TOKEN;
}

static void *filters_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct adapter *adap = seq->private;

	(*pos)++;
	return filters_get_idx(adap, *pos);
}

static void filters_stop(struct seq_file *seq, void *v)
{
}

int filters_open(struct inode *inode, struct file *file)
{
	struct t4_linux_debugfs_data *d = inode->i_private;
	struct adapter *adap = d->adap;
	int res;

	res = seq_open(file, &filters_seq_ops);
	if (!res) {
		struct seq_file *seq = file->private_data;

		seq->private = adap;
	}
	return res;
}

const struct file_operations filters_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = filters_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
};
#endif

static inline void *cxgb4_filter_normal_debugfs_get_idx(struct adapter *adap,
                                                        loff_t pos)
{
	if (pos > (adap->tids.nftids + adap->tids.nsftids +
		   adap->tids.nhpftids))
                return NULL;

        return (void *)(uintptr_t)(pos + 1);
}

static void *cxgb4_filter_normal_debugfs_start(struct seq_file *seq,
                                               loff_t *pos)
{
        struct adapter *adap = seq->private;

        return (*pos ? cxgb4_filter_normal_debugfs_get_idx(adap, *pos) :
                       SEQ_START_TOKEN);
}

static void *cxgb4_filter_normal_debugfs_next(struct seq_file *seq, void *v,
                                              loff_t *pos)
{
        struct adapter *adap = seq->private;

        (*pos)++;
        return cxgb4_filter_normal_debugfs_get_idx(adap, *pos);
}

static void cxgb4_filter_normal_debugfs_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations filters_seq_ops = {
        .start = cxgb4_filter_normal_debugfs_start,
        .next  = cxgb4_filter_normal_debugfs_next,
        .stop  = cxgb4_filter_normal_debugfs_stop,
        .show  = cxgb4_filter_normal_debugfs_show
};

static int cxgb4_filter_normal_debugfs_open(struct inode *inode,
                                            struct file *file)
{
        struct t4_linux_debugfs_data *d = inode->i_private;
        struct adapter *adap = d->adap;
        int res;

        res = seq_open(file, &filters_seq_ops);
        if (!res) {
                struct seq_file *seq = file->private_data;

                seq->private = adap;
        }
        return res;
}

const struct file_operations filters_debugfs_fops = {
        .owner   = THIS_MODULE,
        .open    = cxgb4_filter_normal_debugfs_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
};

static int cxgb4_filter_hash_debugfs_show(struct seq_file *seq, void *v)
{
        struct adapter *adap = seq->private;
        u32 fconf, tpiconf, chip_ver;
        u8 first, last;
        int i;

        fconf = adap->params.tp.vlan_pri_map;
        tpiconf = adap->params.tp.ingress_config;
        chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
        if (chip_ver >= CHELSIO_T7) {
                first = T7_FT_FIRST_S;
                last = T7_FT_LAST_S;
        } else {
                first = FT_FIRST_S;
                last = FT_LAST_S;
        }

        if (v == SEQ_START_TOKEN) {
                seq_puts(seq, "[[Legend: "
                         "'!' => locked; "
                         "'+' => pending set; "
                         "'-' => pending clear]]\n");
                seq_puts(seq, " Idx                          Hits");
                seq_puts(seq, "            Hit-Bytes");
                for (i = first; i <= last; i++)
                        cxgb4_filter_debugfs_show_field_name(seq, chip_ver,
                                                             i, fconf, tpiconf);
                seq_printf(seq, " %65s %65s %9s %9s %s\n",
                           "LIP", "FIP", "LPORT", "FPORT", "Action");
        } else {
                int fidx = (uintptr_t)v - 2;
                struct filter_entry *f;
                spinlock_t *lock; /* Lock for accessing ehash table */

                if (!is_hashfilter(adap))
                        return 0;

		f = adap->tids.tid_tab[fidx];
                if (!f)
                        return 0;

                spin_lock_bh(lock);
                /* If this entry isn't filled in just return */
                if (!f->valid) {
                        spin_unlock_bh(lock);
                        return 0;
                }

		cxgb4_filter_debugfs_display(seq, fidx + adap->tids.tid_base,
					     f, 1);
                spin_unlock_bh(lock);
        }
        return 0;
}

static inline void *cxgb4_filter_hash_debugfs_get_idx(struct adapter *adap,
                                                      loff_t pos)
{
        if (!is_hashfilter(adap))
                return NULL;

	if (pos > (adap->tids.ntids))
                return NULL;

        return (void *)(uintptr_t)(pos + 1);
}

static void *cxgb4_filter_hash_debugfs_start(struct seq_file *seq, loff_t *pos)
{
        struct adapter *adap = seq->private;

        return (*pos ? cxgb4_filter_hash_debugfs_get_idx(adap, *pos) :
                       SEQ_START_TOKEN);
}

static void *cxgb4_filter_hash_debugfs_next(struct seq_file *seq, void *v,
                                            loff_t *pos)
{
        struct adapter *adap = seq->private;

        (*pos)++;
        return cxgb4_filter_hash_debugfs_get_idx(adap, *pos);
}

static void cxgb4_filter_hash_debugfs_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations hash_filters_seq_ops = {
        .start = cxgb4_filter_hash_debugfs_start,
        .next  = cxgb4_filter_hash_debugfs_next,
        .stop  = cxgb4_filter_hash_debugfs_stop,
        .show  = cxgb4_filter_hash_debugfs_show
};

static int cxgb4_filter_hash_debugfs_open(struct inode *inode,
                                          struct file *file)
{
        struct t4_linux_debugfs_data *d = inode->i_private;
        struct adapter *adap = d->adap;
        int res;

        res = seq_open(file, &hash_filters_seq_ops);
        if (!res) {
                struct seq_file *seq = file->private_data;

                seq->private = adap;
        }
        return res;
}

const struct file_operations hash_filters_debugfs_fops = {
        .owner   = THIS_MODULE,
        .open    = cxgb4_filter_hash_debugfs_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
};

//---------------------------------- old changes doubtful ------------------------------------------
static bool is_addr_all_mask(u8 *ipmask, int family)
{
	if (family == AF_INET) {
		struct in_addr *addr;

		addr = (struct in_addr *)ipmask;
		if (addr->s_addr == htonl(0xffffffff))
			return true;
	} else if (family == AF_INET6) {
		struct in6_addr *addr6;

		addr6 = (struct in6_addr *)ipmask;
		if (addr6->s6_addr32[0] == htonl(0xffffffff) &&
		    addr6->s6_addr32[1] == htonl(0xffffffff) &&
		    addr6->s6_addr32[2] == htonl(0xffffffff) &&
		    addr6->s6_addr32[3] == htonl(0xffffffff))
			return true;
	}
	return false;
}

static bool is_inaddr_any(u8 *ip, int family)
{
	int addr_type;

	if (family == AF_INET) {
		struct in_addr *addr;

		addr = (struct in_addr *)ip;
		if (addr->s_addr == htonl(INADDR_ANY))
			return true;
	} else if (family == AF_INET6) {
		struct in6_addr *addr6;

		addr6 = (struct in6_addr *)ip;
		addr_type = ipv6_addr_type((const struct in6_addr *)
					   &addr6);
		if (addr_type == IPV6_ADDR_ANY)
			return true;
	}
	return false;
}

bool is_filter_exact_match(struct adapter *adap,
			   struct ch_filter_specification *fs)
{
	struct tp_params *tp = &adap->params.tp;
	u64 hash_filter_mask = tp->hash_filter_mask;
	u64 ntuple_mask = 0;

	if (!is_hashfilter(adap))
		return false;

	if ((atomic_read(&adap->tids.hash_tids_in_use) +
	     atomic_read(&adap->tids.tids_in_use)) >=
	    (adap->tids.nhash + (adap->tids.stid_base - adap->tids.tid_base)))
		return false;

	 /* Keep tunnel VNI match disabled for hash-filters for now */
	if (fs->mask.encap_vld)
		return false;

	if (fs->type) {
		if (is_inaddr_any(fs->val.fip, AF_INET6) ||
		    !is_addr_all_mask(fs->mask.fip, AF_INET6))
			return false;

		if (is_inaddr_any(fs->val.lip, AF_INET6) ||
		    !is_addr_all_mask(fs->mask.lip, AF_INET6))
			return false;
	} else {
		if (is_inaddr_any(fs->val.fip, AF_INET) ||
		    !is_addr_all_mask(fs->mask.fip, AF_INET))
			return false;

		if (is_inaddr_any(fs->val.lip, AF_INET) ||
		    !is_addr_all_mask(fs->mask.lip, AF_INET))
			return false;
	}

	if (!fs->val.lport || fs->mask.lport != 0xffff)
		return false;

	if (!fs->val.fport || fs->mask.fport != 0xffff)
		return false;

	/* calculate tuple mask and compare with mask configured in hw */
	if (tp->fcoe_shift >= 0)
		ntuple_mask |= (u64)fs->mask.fcoe << tp->fcoe_shift;

	if (tp->port_shift >= 0)
		ntuple_mask |= (u64)fs->mask.iport << tp->port_shift;

	if (tp->vnic_shift >= 0) {
		if ((adap->params.tp.ingress_config & VNIC_F))
			ntuple_mask |= (u64)fs->mask.pfvf_vld << tp->vnic_shift;
		else
			ntuple_mask |= (u64)fs->mask.ovlan_vld <<
				tp->vnic_shift;
	}

	if (tp->vlan_shift >= 0)
		ntuple_mask |= (u64)fs->mask.ivlan << tp->vlan_shift;

	if (tp->tos_shift >= 0)
		ntuple_mask |= (u64)fs->mask.tos << tp->tos_shift;

	if (tp->protocol_shift >= 0)
		ntuple_mask |= (u64)fs->mask.proto << tp->protocol_shift;

	if (tp->ethertype_shift >= 0)
		ntuple_mask |= (u64)fs->mask.ethtype << tp->ethertype_shift;

	if (tp->macmatch_shift >= 0)
		ntuple_mask |= (u64)fs->mask.macidx << tp->macmatch_shift;

	if (tp->matchtype_shift >= 0)
		ntuple_mask |= (u64)fs->mask.matchtype << tp->matchtype_shift;

	if (tp->frag_shift >= 0)
		ntuple_mask |= (u64)fs->mask.frag << tp->frag_shift;

	if (ntuple_mask != hash_filter_mask)
		return false;

	return true;
}
