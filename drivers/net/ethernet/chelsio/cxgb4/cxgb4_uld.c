/*
 * cxgb4_uld.c:Chelsio Upper Layer Driver Interface for T4/T5/T6 SGE management
 *
 * Copyright (c) 2016 Chelsio Communications, Inc. All rights reserved.
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
 *
 *  Written by: Atul Gupta (atul.gupta@chelsio.com)
 *  Written by: Hariprasad Shenai (hariprasad@chelsio.com)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/export.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/pci.h>

#include "cxgb4.h"
#include "cxgb4_uld.h"
#include "cxgb4_filter.h"
#include "srq.h"
#include "t4_regs.h"
#include "t4fw_api.h"
#include "t4_msg.h"

#define for_each_uldrxq(m, i) for (i = 0; i < ((m)->nrxq + (m)->nciq); i++)

//BEGIN------------------------ new cxgb4_uld.c from outbox -----------------------------BEGIN

/* Return the channel of the ingress queue with the given qid.
 */
static unsigned int rxq_to_chan(const struct sge *p, unsigned int qid)
{
       qid -= p->ingr_start;
       return netdev2pinfo(p->ingr_map[qid]->netdev)->tx_chan;
}

bool cxgb4_uld_sendpath_enabled(struct adapter *adap)
{
       return adap->params.tx_sendpath;
}

bool cxgb4_uld_supported_any(struct adapter *adap)
{
       return !!adap->params.offload;
}

bool cxgb4_uld_supported(struct adapter *adap, enum cxgb4_uld_type uld)
{
       return !!(adap->params.offload & BIT(uld));
}

static void cxgb4_uld_enable(struct adapter *adap, enum cxgb4_uld_type uld)
{
       adap->params.offload |= BIT(uld);
}

static void cxgb4_uld_disable(struct adapter *adap, enum cxgb4_uld_type uld)
{
       adap->params.offload &= ~BIT(uld);
}

const char *cxgb4_uld_type_to_name(enum cxgb4_uld_type uld)
{
       switch (uld) {
       case CXGB4_ULD_RDMA:
               return "rdma";
       case CXGB4_ULD_ISCSI:
               return "iscsi";
       case CXGB4_ULD_ISCSIT:
               return "iscsit";
       case CXGB4_ULD_TYPE_NVME_TCP_HOST:
               return "nvmeh";
       case CXGB4_ULD_TYPE_NVME_TCP_TARGET:
               return "nvmet";
       case CXGB4_ULD_TYPE_CSTOR:
               return "cstor";
       case CXGB4_ULD_CRYPTO:
               return "crypto";
       case CXGB4_ULD_TYPE_TOE:
               return "toe";
       case CXGB4_ULD_TYPE_CHTCP:
               return "chtcp";
       case CXGB4_ULD_IPSEC:
               return "ipsec";
       default:
               break;
       }

       return NULL;
}

static void cxgb4_uld_cleanup_toe(struct adapter *adap)
{
#ifdef CONFIG_PO_FCOE
       cxgb_fcoe_exit_ddp(adap);
#endif /* CONFIG_PO_FCOE */
       adap->params.ofldq_wr_cred = 0;
       memset(&adap->uld_inst.vres.ddp, 0, sizeof(adap->uld_inst.vres.ddp));
       cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_TOE);
       cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_CHTCP);
}

static int cxgb4_uld_init_toe(struct adapter *adap,
                             const struct fw_caps_config_cmd *caps_cmd)
{
       unsigned int chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
       u32 params[7], val[7];
       int ret;

       /* Query offload-related parameters */
       params[0] = FW_PARAM_PFVF(TDDP_START);
       params[1] = FW_PARAM_PFVF(TDDP_END);
       params[2] = FW_PARAM_DEV(FLOWC_BUFFIFO_SZ);
       ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 3, params, val);
       if (ret < 0)
               return ret;
       adap->uld_inst.vres.ddp.start = val[0];
       adap->uld_inst.vres.ddp.size = val[1] - val[0] + 1;
       adap->params.ofldq_wr_cred = val[2];

       if (caps_cmd->ofldcaps & cpu_to_be16(FW_CAPS_CONFIG_OFLD_SENDPATH)) {
               params[0] = FW_PARAM_PFVF(SQRQ_START);
               params[1] = FW_PARAM_PFVF(SQRQ_END);
               ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2,
                                     params, val);
               if (ret < 0) {
                       adap->params.tx_sendpath = false;
               } else {
                       adap->params.tx_sendpath = true;
                       adap->uld_inst.vres.sendpath_qp.start = val[0];
                       adap->uld_inst.vres.sendpath_qp.size = val[1] - val[0] + 1;
               }
       }

#ifdef CONFIG_PO_FCOE
       if (ntohs(caps_cmd->fcoecaps) & FW_CAPS_CONFIG_POFCOE_TARGET)
               cxgb_fcoe_init_ddp(adap);
#endif /* CONFIG_PO_FCOE */

       if (chip_ver >= CHELSIO_T7 && adap->params.num_up_cores > 1) {
               params[0] = FW_PARAM_DEV(TID_QID_SEL_MASK);
               ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
                                     params, val);
               adap->params.tid_qid_sel_mask = (ret == 0 ? val[0] : 0);
               if (adap->params.tid_qid_sel_mask)
                       adap->params.tid_qid_sel_shift =
                               ffs(adap->params.tid_qid_sel_mask) - 1;
               else
                       adap->params.tid_qid_sel_shift = 0;
       }

       cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_TOE);
       cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_CHTCP);
       return 0;
}

static void cxgb4_uld_cleanup_rdma(struct adapter *adap)
{
       if (adap->uld_inst.oc_mw_kva) {
               iounmap(adap->uld_inst.oc_mw_kva);
               adap->uld_inst.oc_mw_kva = 0;
               adap->uld_inst.oc_mw_pa = 0;
       }

       adap->params.write_cmpl_support = 0;
       adap->params.write_w_imm_support = 0;
       adap->params.max_ird_adapter = 0;
       adap->params.max_ordird_qp = 0;
       cxgb4_srq_cleanup(adap);
       memset(&adap->uld_inst.vres.ocq, 0, sizeof(adap->uld_inst.vres.ocq));
       memset(&adap->uld_inst.vres.cq, 0, sizeof(adap->uld_inst.vres.cq));
       memset(&adap->uld_inst.vres.qp, 0, sizeof(adap->uld_inst.vres.qp));
       memset(&adap->uld_inst.vres.pbl, 0, sizeof(adap->uld_inst.vres.pbl));
       memset(&adap->uld_inst.vres.stor_pbl, 0, sizeof(adap->uld_inst.vres.stor_pbl));
       memset(&adap->uld_inst.vres.rq, 0, sizeof(adap->uld_inst.vres.rq));
       memset(&adap->uld_inst.vres.stag, 0, sizeof(adap->uld_inst.vres.stag));
       memset(&adap->uld_inst.vres.stor_stag, 0, sizeof(adap->uld_inst.vres.stor_stag));
       cxgb4_uld_disable(adap, CXGB4_ULD_RDMA);
       cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_NVME_TCP_HOST);
       cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_NVME_TCP_TARGET);
       cxgb4_uld_disable(adap, CXGB4_ULD_TYPE_CSTOR);
}

static int cxgb4_uld_init_rdma(struct adapter *adap,
                              const struct fw_caps_config_cmd *caps_cmd)
{
       u32 params[7], val[7];
       int ret;

       params[0] = FW_PARAM_PFVF(STAG_START);
       params[1] = FW_PARAM_PFVF(STAG_END);
       params[2] = FW_PARAM_PFVF(RQ_START);
       params[3] = FW_PARAM_PFVF(RQ_END);
       params[4] = FW_PARAM_PFVF(PBL_START);
       params[5] = FW_PARAM_PFVF(PBL_END);
       ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 6, params, val);
       if (ret < 0)
               return ret;
       adap->uld_inst.vres.stag.start = val[0];
       adap->uld_inst.vres.stag.size = val[1] - val[0] + 1;
       adap->uld_inst.vres.rq.start = val[2];
       adap->uld_inst.vres.rq.size = val[3] - val[2] + 1;
       adap->uld_inst.vres.pbl.start = val[4];
       adap->uld_inst.vres.pbl.size = val[5] - val[4] + 1;

       params[0] = FW_PARAM_PFVF(SQRQ_START);
       params[1] = FW_PARAM_PFVF(SQRQ_END);
       params[2] = FW_PARAM_PFVF(CQ_START);
       params[3] = FW_PARAM_PFVF(CQ_END);
       params[4] = FW_PARAM_PFVF(OCQ_START);
       params[5] = FW_PARAM_PFVF(OCQ_END);
       ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 6, params, val);
       if (ret < 0)
               goto out_err;
       adap->uld_inst.vres.qp.start = val[0];
       adap->uld_inst.vres.qp.size = val[1] - val[0] + 1;
       adap->uld_inst.vres.cq.start = val[2];
       adap->uld_inst.vres.cq.size = val[3] - val[2] + 1;
       adap->uld_inst.vres.ocq.start = val[4];
       adap->uld_inst.vres.ocq.size = val[5] - val[4] + 1;

       params[0] = FW_PARAM_PFVF(SRQ_START);
       params[1] = FW_PARAM_PFVF(SRQ_END);
       ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
       if (!ret) {
               adap->uld_inst.vres.srq.start = val[0];
               adap->uld_inst.vres.srq.size = val[1] - val[0] + 1;
               if (adap->uld_inst.vres.srq.size) {
                       ret = cxgb4_srq_init(adap, adap->uld_inst.vres.srq.size);
                       if (ret < 0) {
                               dev_warn(adap->pdev_dev,
                                        "could not allocate SRQ, continuing\n");
                               ret = 0;
                       }
               }
       }

       params[0] = FW_PARAM_DEV(MAXORDIRD_QP);
       params[1] = FW_PARAM_DEV(MAXIRD_ADAPTER);
       ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
       if (ret < 0) {
               adap->params.max_ordird_qp = 8;
               adap->params.max_ird_adapter = 32 * adap->tidinfo.tids.size;;
               ret = 0;
       } else {
               adap->params.max_ordird_qp = val[0];
               adap->params.max_ird_adapter = val[1];
       }
       dev_info(adap->pdev_dev, "max_ordird_qp %d max_ird_adapter %d\n",
                adap->params.max_ordird_qp, adap->params.max_ird_adapter);

       /* Enable WRITE_WITH_IMMEDIATE if FW supports it */
       params[0] = FW_PARAM_DEV(RDMA_WRITE_WITH_IMM);
       ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, params, val);
       if (!ret && val[0] != 0)
               adap->params.write_w_imm_support = 1;

       /* Enable WRITE_CMPL if FW supports it */
       params[0] = FW_PARAM_DEV(RI_WRITE_CMPL_WR);
       ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, params, val);
       if (!ret && val[0] != 0)
               adap->params.write_cmpl_support = 1;

       cxgb4_uld_enable(adap, CXGB4_ULD_RDMA);

       if (caps_cmd->nvmecaps) {
               bool divide_resources = false;

               if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_NVME_TCP_HOST)) {
                       cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_NVME_TCP_HOST);
                       divide_resources = true;
               }

               if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_NVME_TCP_TARGET)) {
                       cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_NVME_TCP_TARGET);
                       divide_resources = true;
               }

               if (cxgb4_modparam_enable_ulds_supported(CXGB4_ULD_TYPE_CSTOR)) {
                       cxgb4_uld_enable(adap, CXGB4_ULD_TYPE_CSTOR);
                       divide_resources = true;
               }

               if (divide_resources) {
                       adap->uld_inst.vres.stag.size /= 2;
                       adap->uld_inst.vres.stor_stag.start = adap->uld_inst.vres.stag.start +
                                                        adap->uld_inst.vres.stag.size;
                       adap->uld_inst.vres.stor_stag.size = adap->uld_inst.vres.stag.size;

                       adap->uld_inst.vres.pbl.size /= 2;
                       adap->uld_inst.vres.stor_pbl.start = adap->uld_inst.vres.pbl.start +
                                                       adap->uld_inst.vres.pbl.size;
                       adap->uld_inst.vres.stor_pbl.size = adap->uld_inst.vres.pbl.size;
               }
       }

       return 0;

out_err:
       cxgb4_uld_cleanup_rdma(adap);
       return ret;
}

static void cxgb4_uld_cleanup_iscsi(struct adapter *adap)
{
       memset(&adap->uld_inst.vres.ppod_edram, 0, sizeof(adap->uld_inst.vres.ppod_edram));
       memset(&adap->uld_inst.vres.iscsi, 0, sizeof(adap->uld_inst.vres.iscsi));
       cxgb4_uld_disable(adap, CXGB4_ULD_ISCSI);
       cxgb4_uld_disable(adap, CXGB4_ULD_ISCSIT);
}

static int cxgb4_uld_init_iscsi(struct adapter *adap,
                               const struct fw_caps_config_cmd *caps_cmd)
{
       u32 params[7], val[7];
       int ret;

       params[0] = FW_PARAM_PFVF(ISCSI_START);
       params[1] = FW_PARAM_PFVF(ISCSI_END);
       ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
       if (ret < 0)
               return ret;
       adap->uld_inst.vres.iscsi.start = val[0];
       adap->uld_inst.vres.iscsi.size = val[1] - val[0] + 1;

       if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T6) {
               params[0] = FW_PARAM_PFVF(PPOD_EDRAM_START);
               params[1] = FW_PARAM_PFVF(PPOD_EDRAM_END);
               ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2,
                                     params, val);
               if (!ret) {
                       adap->uld_inst.vres.ppod_edram.start = val[0];
                       adap->uld_inst.vres.ppod_edram.size = val[1] - val[0] + 1;
                       dev_info(adap->pdev_dev,
                                "iscsi_caps: ppod edram start 0x%x end 0x%x size 0x%x\n",
                                val[0], val[1],
                                adap->uld_inst.vres.ppod_edram.size);
               }
       }

       cxgb4_uld_enable(adap, CXGB4_ULD_ISCSI);
       cxgb4_uld_enable(adap, CXGB4_ULD_ISCSIT);
       return 0;
}

static void cxgb4_uld_cleanup_crypto(struct adapter *adap)
{
       adap->params.crypto = 0;
       memset(&adap->uld_inst.vres.key, 0, sizeof(adap->uld_inst.vres.key));
       adap->uld_inst.vres.ncrypto_fc = 0;
       cxgb4_uld_disable(adap, CXGB4_ULD_CRYPTO);
}

static int cxgb4_uld_init_crypto(struct adapter *adap,
                                const struct fw_caps_config_cmd *caps_cmd)
{
       u16 cryptocaps = ntohs(caps_cmd->cryptocaps);
       u32 params[7], val[7];
       unsigned int chip_ver;
       int ret;

       chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

       if (cryptocaps & FW_CAPS_CONFIG_CRYPTO_LOOKASIDE) {
               params[0] = FW_PARAM_PFVF(NCRYPTO_LOOKASIDE);
               ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
                                     params, val);
               if (ret < 0) {
                       if (ret != -EINVAL)
                               return ret;
               } else {
                       adap->uld_inst.vres.ncrypto_fc = val[0];
               }
       }

       if (cryptocaps & FW_CAPS_CONFIG_TLS_INLINE) {
               params[0] = FW_PARAM_PFVF(TLS_START);
               params[1] = FW_PARAM_PFVF(TLS_END);
               ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2,
                                     params, val);
               if (ret < 0)
                       goto out_err;
               adap->uld_inst.vres.key.start = val[0];
               adap->uld_inst.vres.key.size = val[1] - val[0] + 1;
               dev_info(adap->pdev_dev, "crypto_caps: key start:%x end:%x\n",
                        val[0], val[1]);
       }

#if IS_ENABLED(CONFIG_CHELSIO_IPSEC_INLINE)
       if (chip_ver == CHELSIO_T7 && cryptocaps & ULP_CRYPTO_IPSEC_INLINE) {
               params[0] = FW_PARAM_PFVF(NIPSEC_TUNNEL);
               ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
                                     params, val);
               if (ret < 0)
                       goto out_err;
               adap->uld_inst.vres.ipsec_max_nic_tunnel = val[0];

               params[0] = FW_PARAM_PFVF(NIPSEC_TRANSPORT);
               ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
                                     params, val);
               if (ret < 0)
                       goto out_err;
               adap->uld_inst.vres.ipsec_max_nic_transport = val[0];
       }

       if (chip_ver == CHELSIO_T7 && cryptocaps & ULP_CRYPTO_OFLD_OVER_IPSEC_INLINE) {
               params[0] = FW_PARAM_PFVF(OFLD_NIPSEC_TUNNEL);
               ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
                                     params, val);
               if (ret < 0)
                       goto out_err;
               adap->uld_inst.vres.ipsec_max_ofld_conn = val[0];
       }
#endif /* CONFIG_CHELSIO_IPSEC_INLINE */

       adap->params.crypto = cryptocaps;

       cxgb4_uld_enable(adap, CXGB4_ULD_CRYPTO);
       return 0;

out_err:
       cxgb4_uld_cleanup_crypto(adap);
       return ret;
}

static void cxgb4_uld_tweak_resources_sendpath(struct adapter *adap)
{
       u32 eq_qpp, npages;

       eq_qpp = t4_sge_get_qpp(adap, SGE_EGRESS_QUEUES_PER_PAGE_PF_A);
       if (!eq_qpp) {
               adap->params.tx_sendpath = false;
               memset(&adap->uld_inst.vres.sendpath_qp, 0,
                      sizeof(adap->uld_inst.vres.sendpath_qp));
               return;
       }

       /* Reserve 1/3 of the pages to SENDPATH */
       npages = (adap->uld_inst.vres.qp.size / (1 << eq_qpp)) / 3;
       adap->uld_inst.vres.sendpath_qp.size = npages * (1 << eq_qpp);
       adap->uld_inst.vres.qp.size -= adap->uld_inst.vres.sendpath_qp.size;
       adap->uld_inst.vres.cq.size -= adap->uld_inst.vres.sendpath_qp.size;
       adap->uld_inst.vres.sendpath_qp.start = adap->uld_inst.vres.qp.start +
                                          adap->uld_inst.vres.qp.size;
}

static void cxgb4_uld_tweak_resources(struct adapter *adap)
{
       if (cxgb4_uld_sendpath_enabled(adap) &&
           cxgb4_uld_supported(adap, CXGB4_ULD_RDMA))
               cxgb4_uld_tweak_resources_sendpath(adap);
}

static void cxgb4_uld_cleanup_resources_sendpath(struct adapter *adap)
{
       ida_destroy(&adap->uld_inst.res.sendpath_res.qp_ida);
}

static void cxgb4_uld_cleanup_resources(struct adapter *adap)
{
       if (cxgb4_uld_sendpath_enabled(adap))
               cxgb4_uld_cleanup_resources_sendpath(adap);
}

static void cxgb4_uld_init_resources_sendpath(struct adapter *adap)
{
       ida_init(&adap->uld_inst.res.sendpath_res.qp_ida);
}

static void cxgb4_uld_init_resources(struct adapter *adap)
{
       if (cxgb4_uld_sendpath_enabled(adap))
               cxgb4_uld_init_resources_sendpath(adap);
}

void cxgb4_uld_cleanup(struct adapter *adap)
{
       cxgb4_uld_cleanup_resources(adap);

       if (cxgb4_uld_supported(adap, CXGB4_ULD_TYPE_TOE))
               cxgb4_uld_cleanup_toe(adap);

       if (cxgb4_uld_supported(adap, CXGB4_ULD_RDMA))
               cxgb4_uld_cleanup_rdma(adap);

       if (cxgb4_uld_supported(adap, CXGB4_ULD_ISCSI))
               cxgb4_uld_cleanup_iscsi(adap);

       if (cxgb4_uld_supported(adap, CXGB4_ULD_CRYPTO))
               cxgb4_uld_cleanup_crypto(adap);

       mutex_destroy(&adap->uld_inst.uld_mutex);
}

int cxgb4_uld_init(struct adapter *adap,
                  const struct fw_caps_config_cmd *caps_cmd)
{
       int ret;

       mutex_init(&adap->uld_inst.uld_mutex);

       /* Disable offload when in kdump kernel */
       if (is_kdump_kernel()) {
               adap->params.offload = 0;
               return 0;
       }

       if (caps_cmd->ofldcaps) {
               ret = cxgb4_uld_init_toe(adap, caps_cmd);
               if (ret < 0) {
                       dev_err(adap->pdev_dev,
                               "Could not initialize TOE, ret: %d\n", ret);
                       goto out_err;
               }
       }

       if (caps_cmd->rdmacaps) {
               ret = cxgb4_uld_init_rdma(adap, caps_cmd);
               if (ret < 0) {
                       dev_warn(adap->pdev_dev,
                                "Could not initialize RDMA, ret: %d. Continuing...\n",
                                ret);
                       ret = 0;
               }
       }

       if (caps_cmd->iscsicaps) {
               ret = cxgb4_uld_init_iscsi(adap, caps_cmd);
               if (ret < 0) {
                       dev_warn(adap->pdev_dev,
                                "Could not initialize iSCSI, ret: %d. Continuing...\n",
                                ret);
                       ret = 0;
               }
       }

       if (caps_cmd->cryptocaps) {
               ret = cxgb4_uld_init_crypto(adap, caps_cmd);
               if (ret < 0) {
                       dev_warn(adap->pdev_dev,
                                "Could not initialize CRYPTO, ret: %d. Continuing...\n",
                                ret);
                       ret = 0;
               }
       }

       cxgb4_uld_tweak_resources(adap);
       cxgb4_uld_init_resources(adap);
       return 0;

out_err:
       mutex_destroy(&adap->uld_inst.uld_mutex);
       return ret;
}
//END------------------------ new cxgb4_uld.c from outbox -----------------------------END

/**
 *     cxgb4_create_server - create an IP server
 *     @dev: the device
 *     @stid: the server TID
 *     @sip: local IP address to bind server to
 *     @sport: the server's TCP port
 *     @vlan: the VLAN header information
 *     @queue: queue to direct messages from this server to
 *
 *     Create an IP server for the given port and address.
 *     Returns <0 on error and one of the %NET_XMIT_* values on success.
 */
int cxgb4_create_server(const struct net_device *dev, unsigned int stid,
                       __be32 sip, __be16 sport, __be16 vlan,
                       unsigned int queue)
{
       unsigned int chan;
       struct sk_buff *skb;
       struct adapter *adap;
       struct cpl_pass_open_req *req;
       int ret;

       skb = alloc_skb(sizeof(*req), GFP_KERNEL);
       if (!skb)
               return -ENOMEM;

       adap = netdev2adap(dev);
       req = __skb_put(skb, sizeof(*req));
       INIT_TP_WR(req, 0);
       OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_PASS_OPEN_REQ, stid));
       req->local_port = sport;
       req->peer_port = htons(0);
       req->local_ip = sip;
       req->peer_ip = htonl(0);
       chan = rxq_to_chan(&adap->sge, queue);
       req->opt0 = cpu_to_be64(TX_CHAN_V(chan));
       req->opt1 = cpu_to_be64(CONN_POLICY_V(CPL_CONN_POLICY_ASK) |
                               SYN_RSS_ENABLE_F | SYN_RSS_QUEUE_V(queue));
       ret = t4_mgmt_tx(adap, skb);
       return net_xmit_eval(ret);
}
EXPORT_SYMBOL(cxgb4_create_server);

/*     cxgb4_create_server6 - create an IPv6 server
 *     @dev: the device
 *     @stid: the server TID
 *     @sip: local IPv6 address to bind server to
 *     @sport: the server's TCP port
 *     @queue: queue to direct messages from this server to
 *
 *     Create an IPv6 server for the given port and address.
 *     Returns <0 on error and one of the %NET_XMIT_* values on success.
 */
int cxgb4_create_server6(const struct net_device *dev, unsigned int stid,
                        const struct in6_addr *sip, __be16 sport,
                        unsigned int queue)
{
       unsigned int chan;
       struct sk_buff *skb;
       struct adapter *adap;
       struct cpl_pass_open_req6 *req;
       int ret;

       skb = alloc_skb(sizeof(*req), GFP_KERNEL);
       if (!skb)
               return -ENOMEM;

       adap = netdev2adap(dev);
       req = __skb_put(skb, sizeof(*req));
       INIT_TP_WR(req, 0);
       OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_PASS_OPEN_REQ6, stid));
       req->local_port = sport;
       req->peer_port = htons(0);
       req->local_ip_hi = *(__be64 *)(sip->s6_addr);
       req->local_ip_lo = *(__be64 *)(sip->s6_addr + 8);
       req->peer_ip_hi = cpu_to_be64(0);
       req->peer_ip_lo = cpu_to_be64(0);
       chan = rxq_to_chan(&adap->sge, queue);
       req->opt0 = cpu_to_be64(TX_CHAN_V(chan));
       req->opt1 = cpu_to_be64(CONN_POLICY_V(CPL_CONN_POLICY_ASK) |
                               SYN_RSS_ENABLE_F | SYN_RSS_QUEUE_V(queue));
       ret = t4_mgmt_tx(adap, skb);
       return net_xmit_eval(ret);
}
EXPORT_SYMBOL(cxgb4_create_server6);

int cxgb4_remove_server(const struct net_device *dev, unsigned int stid,
                       unsigned int queue, bool ipv6)
{
       struct sk_buff *skb;
       struct adapter *adap;
       struct cpl_close_listsvr_req *req;
       int ret;

       adap = netdev2adap(dev);

       skb = alloc_skb(sizeof(*req), GFP_KERNEL);
       if (!skb)
               return -ENOMEM;

       req = __skb_put(skb, sizeof(*req));
       INIT_TP_WR(req, 0);
       OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_CLOSE_LISTSRV_REQ, stid));
       req->reply_ctrl = htons(NO_REPLY_V(0) | (ipv6 ? LISTSVR_IPV6_V(1) :
                               LISTSVR_IPV6_V(0)) | QUEUENO_V(queue));
       ret = t4_mgmt_tx(adap, skb);
       return net_xmit_eval(ret);
}
EXPORT_SYMBOL(cxgb4_remove_server);

/* Flush the aggregated lro sessions */
static void uldrx_flush_handler(struct sge_rspq *q)
{
	if (cxgb4_ulds[q->uld].lro_flush)
		cxgb4_ulds[q->uld].lro_flush(&q->lro_mgr);
}

/**
 *	uldrx_handler - response queue handler for ULD queues
 *	@q: the response queue that received the packet
 *	@rsp: the response queue descriptor holding the offload message
 *	@gl: the gather list of packet fragments
 *
 *	Deliver an ingress offload packet to a ULD.  All processing is done by
 *	the ULD, we just maintain statistics.
 */
static int uldrx_handler(struct sge_rspq *q, const __be64 *rsp,
			 const struct pkt_gl *gl)
{
	struct adapter *adap = q->adap;
	struct sge_ofld_rxq *rxq = container_of(q, struct sge_ofld_rxq, rspq);
	int ret;

	/* FW can send CPLs encapsulated in a CPL_FW4_MSG */
	if (((const struct rss_header *)rsp)->opcode == CPL_FW4_MSG &&
			((const struct cpl_fw4_msg *)(rsp + 1))->type == FW_TYPE_RSSCPL)
		rsp += 2;

	if (q->flush_handler)
		ret = cxgb4_ulds[q->uld].lro_rx_handler(adap->uld_handle[q->uld],
				rsp, gl, &q->lro_mgr,
				&q->napi);
	else
		ret = cxgb4_ulds[q->uld].rx_handler(adap->uld_handle[q->uld],
				rsp, gl);

	if (ret) {
		rxq->stats.nomem++;
		return -1;
	}

	if (!gl)
		rxq->stats.imm++;
	else if (gl == CXGB4_MSG_AN)
		rxq->stats.an++;
	else
		rxq->stats.pkts++;
	return 0;
}

static int alloc_uld_rxqs(struct adapter *adap,
			  struct sge_uld_rxq_info *rxq_info, bool lro)
{
	unsigned int nq = rxq_info->nrxq + rxq_info->nciq;
	struct sge_ofld_rxq *q = rxq_info->uldrxq;
	unsigned short *ids = rxq_info->rspq_id;
	int i, err, msi_idx, que_idx = 0;
	struct sge *s = &adap->sge;
	unsigned int per_chan;

	per_chan = rxq_info->nrxq / adap->params.nports;

	if (adap->flags & CXGB4_USING_MSIX)
		msi_idx = 1;
	else
		msi_idx = -((int)s->intrq.abs_id + 1);

	for (i = 0; i < nq; i++, q++) {
		if (i == rxq_info->nrxq) {
			/* start allocation of concentrator queues */
			per_chan = rxq_info->nciq / adap->params.nports;
			que_idx = 0;
		}

		if (msi_idx >= 0) {
			msi_idx = cxgb4_get_msix_idx_from_bmap(adap);
			if (msi_idx < 0) {
				err = -ENOSPC;
				goto freeout;
			}

			snprintf(adap->msix_info[msi_idx].desc,
				 sizeof(adap->msix_info[msi_idx].desc),
				 "%s-%s%d",
				 adap->port[0]->name, rxq_info->name, i);

			q->msix = &adap->msix_info[msi_idx];
		}
		err = t4_sge_alloc_rxq(adap, &q->rspq, false,
				       adap->port[que_idx++ / per_chan],
				       msi_idx,
				       q->fl.size ? &q->fl : NULL,
				       uldrx_handler,
				       lro ? uldrx_flush_handler : NULL,
				       0);
		if (err)
			goto freeout;

		memset(&q->stats, 0, sizeof(q->stats));
		if (ids)
			ids[i] = q->rspq.abs_id;
	}
	return 0;
freeout:
	q = rxq_info->uldrxq;
	for ( ; i; i--, q++) {
		if (q->rspq.desc)
			free_rspq_fl(adap, &q->rspq,
				     q->fl.size ? &q->fl : NULL);
		if (q->msix)
			cxgb4_free_msix_idx_in_bmap(adap, q->msix->idx);
	}
	return err;
}
static int
setup_sge_queues_uld(struct adapter *adap, unsigned int uld_type, bool lro)
{
	struct sge_uld_rxq_info *rxq_info = adap->sge.uld_rxq_info[uld_type];
	int i, ret;

	ret = alloc_uld_rxqs(adap, rxq_info, lro);
	if (ret)
		return ret;

	/* Tell uP to route control queue completions to rdma rspq */
	if (adap->flags & CXGB4_FULL_INIT_DONE && uld_type == CXGB4_ULD_RDMA) {
		struct sge *s = &adap->sge;
		unsigned int cmplqid;
		u32 param, cmdop;

		cmdop = FW_PARAMS_PARAM_DMAQ_EQ_CMPLIQID_CTRL;
		for_each_port(adap, i) {
			cmplqid = rxq_info->uldrxq[i].rspq.cntxt_id;
			param = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_DMAQ) |
				 FW_PARAMS_PARAM_X_V(cmdop) |
				 FW_PARAMS_PARAM_YZ_V(s->ctrlq[i].q.cntxt_id));
			ret = t4_set_params(adap, adap->mbox, adap->pf,
					    0, 1, &param, &cmplqid);
		}
	}
	return ret;
}

static void t4_free_uld_rxqs(struct adapter *adap, int n,
			     struct sge_ofld_rxq *q)
{
	for ( ; n; n--, q++) {
		if (q->rspq.desc)
			free_rspq_fl(adap, &q->rspq,
				     q->fl.size ? &q->fl : NULL);
	}
}

static void free_sge_queues_uld(struct adapter *adap, unsigned int uld_type)
{
	struct sge_uld_rxq_info *rxq_info = adap->sge.uld_rxq_info[uld_type];

	if (adap->flags & CXGB4_FULL_INIT_DONE && uld_type == CXGB4_ULD_RDMA) {
		struct sge *s = &adap->sge;
		u32 param, cmdop, cmplqid = 0;
		int i;

		cmdop = FW_PARAMS_PARAM_DMAQ_EQ_CMPLIQID_CTRL;
		for_each_port(adap, i) {
			param = (FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_DMAQ) |
				 FW_PARAMS_PARAM_X_V(cmdop) |
				 FW_PARAMS_PARAM_YZ_V(s->ctrlq[i].q.cntxt_id));
			t4_set_params(adap, adap->mbox, adap->pf,
				      0, 1, &param, &cmplqid);
		}
	}

	if (rxq_info->nciq)
		t4_free_uld_rxqs(adap, rxq_info->nciq,
				 rxq_info->uldrxq + rxq_info->nrxq);
	t4_free_uld_rxqs(adap, rxq_info->nrxq, rxq_info->uldrxq);
}

static int cfg_queues_uld(struct adapter *adap, unsigned int uld_type,
			  const struct cxgb4_uld_info *uld_info)
{
	struct sge *s = &adap->sge;
	struct sge_uld_rxq_info *rxq_info;
	int i, nrxq, ciq_size;

	rxq_info = kzalloc_obj(*rxq_info);
	if (!rxq_info)
		return -ENOMEM;

	if (adap->flags & CXGB4_USING_MSIX && uld_info->nrxq > s->nqs_per_uld) {
		i = s->nqs_per_uld;
		rxq_info->nrxq = roundup(i, adap->params.nports);
	} else {
		i = min_t(int, uld_info->nrxq,
			  num_online_cpus());
		rxq_info->nrxq = roundup(i, adap->params.nports);
	}
	if (!uld_info->ciq) {
		rxq_info->nciq = 0;
	} else  {
		if (adap->flags & CXGB4_USING_MSIX)
			rxq_info->nciq = min_t(int, s->nqs_per_uld,
					       num_online_cpus());
		else
			rxq_info->nciq = min_t(int, MAX_OFLD_QSETS,
					       num_online_cpus());
		rxq_info->nciq = ((rxq_info->nciq / adap->params.nports) *
				  adap->params.nports);
		rxq_info->nciq = max_t(int, rxq_info->nciq,
				       adap->params.nports);
	}

	nrxq = rxq_info->nrxq + rxq_info->nciq; /* total rxq's */
	rxq_info->uldrxq = kzalloc_objs(struct sge_ofld_rxq, nrxq);
	if (!rxq_info->uldrxq) {
		kfree(rxq_info);
		return -ENOMEM;
	}

	rxq_info->rspq_id = kcalloc(nrxq, sizeof(unsigned short), GFP_KERNEL);
	if (!rxq_info->rspq_id) {
		kfree(rxq_info->uldrxq);
		kfree(rxq_info);
		return -ENOMEM;
	}

	for (i = 0; i < rxq_info->nrxq; i++) {
		struct sge_ofld_rxq *r = &rxq_info->uldrxq[i];

		init_rspq(adap, &r->rspq, 5, 1, uld_info->rxq_size, 64);
		r->rspq.uld = uld_type;
		r->fl.size = 72;
	}

	ciq_size = 64 + adap->uld_inst.vres.cq.size + adap->tids.nftids;
	if (ciq_size > SGE_MAX_IQ_SIZE) {
		dev_warn(adap->pdev_dev, "CIQ size too small for available IQs\n");
		ciq_size = SGE_MAX_IQ_SIZE;
	}

	for (i = rxq_info->nrxq; i < nrxq; i++) {
		struct sge_ofld_rxq *r = &rxq_info->uldrxq[i];

		init_rspq(adap, &r->rspq, 5, 1, ciq_size, 64);
		r->rspq.uld = uld_type;
	}

	memcpy(rxq_info->name, uld_info->name, IFNAMSIZ);
	adap->sge.uld_rxq_info[uld_type] = rxq_info;

	return 0;
}

static void free_queues_uld(struct adapter *adap, unsigned int uld_type)
{
	struct sge_uld_rxq_info *rxq_info = adap->sge.uld_rxq_info[uld_type];

	adap->sge.uld_rxq_info[uld_type] = NULL;
	kfree(rxq_info->rspq_id);
	kfree(rxq_info->uldrxq);
	kfree(rxq_info);
}

static int
request_msix_queue_irqs_uld(struct adapter *adap, unsigned int uld_type)
{
	struct sge_uld_rxq_info *rxq_info = adap->sge.uld_rxq_info[uld_type];
	struct msix_info *minfo;
	unsigned int idx;
	int err = 0;

	for_each_uldrxq(rxq_info, idx) {
		minfo = rxq_info->uldrxq[idx].msix;
		err = request_irq(minfo->vec,
				  t4_sge_intr_msix, 0,
				  minfo->desc,
				  &rxq_info->uldrxq[idx].rspq);
		if (err)
			goto unwind;

		cxgb4_set_msix_aff(adap, minfo->vec,
				   &minfo->aff_mask, idx);
	}
	return 0;

unwind:
	while (idx-- > 0) {
		minfo = rxq_info->uldrxq[idx].msix;
		cxgb4_clear_msix_aff(minfo->vec, minfo->aff_mask);
		cxgb4_free_msix_idx_in_bmap(adap, minfo->idx);
		free_irq(minfo->vec, &rxq_info->uldrxq[idx].rspq);
	}
	return err;
}

static void
free_msix_queue_irqs_uld(struct adapter *adap, unsigned int uld_type)
{
	struct sge_uld_rxq_info *rxq_info = adap->sge.uld_rxq_info[uld_type];
	struct msix_info *minfo;
	unsigned int idx;

	for_each_uldrxq(rxq_info, idx) {
		minfo = rxq_info->uldrxq[idx].msix;
		cxgb4_clear_msix_aff(minfo->vec, minfo->aff_mask);
		cxgb4_free_msix_idx_in_bmap(adap, minfo->idx);
		free_irq(minfo->vec, &rxq_info->uldrxq[idx].rspq);
	}
}

static void enable_rx_uld(struct adapter *adap, unsigned int uld_type)
{
	struct sge_uld_rxq_info *rxq_info = adap->sge.uld_rxq_info[uld_type];
	int idx;

	for_each_uldrxq(rxq_info, idx) {
		struct sge_rspq *q = &rxq_info->uldrxq[idx].rspq;

		if (!q)
			continue;

		cxgb4_enable_rx(adap, q);
	}
}

static void quiesce_rx_uld(struct adapter *adap, unsigned int uld_type)
{
	struct sge_uld_rxq_info *rxq_info = adap->sge.uld_rxq_info[uld_type];
	int idx;

	for_each_uldrxq(rxq_info, idx) {
		struct sge_rspq *q = &rxq_info->uldrxq[idx].rspq;

		if (!q)
			continue;

		cxgb4_quiesce_rx(q);
	}
}

static void
free_sge_txq_uld(struct adapter *adap, struct sge_uld_txq_info *txq_info)
{
	int nq = txq_info->ntxq;
	int i;

	for (i = 0; i < nq; i++) {
		struct sge_uld_txq *txq = &txq_info->uldtxq[i];

		if (txq->q.desc) {
			tasklet_kill(&txq->qresume_tsk);
			t4_ofld_eq_free(adap, adap->mbox, adap->pf, 0,
					txq->q.cntxt_id);
			free_tx_desc(adap, &txq->q, txq->q.in_use, false);
			kfree(txq->q.sdesc);
			__skb_queue_purge(&txq->sendq);
			free_txq(adap, &txq->q);
		}
	}
}

#if 0
// __SS__ commenting for now
static int
alloc_sge_txq_uld(struct adapter *adap, struct sge_uld_txq_info *txq_info,
		  unsigned int uld_type)
{
	struct sge *s = &adap->sge;
	int nq = txq_info->ntxq;
	int i, j, err;

	j = nq / adap->params.nports;
	for (i = 0; i < nq; i++) {
		struct sge_uld_txq *txq = &txq_info->uldtxq[i];

		txq->q.size = 1024;
		err = t4_sge_alloc_uld_txq(adap, txq, adap->port[i / j],
					   s->fw_evtq.cntxt_id, uld_type);
		if (err)
			goto freeout;
	}
	return 0;
freeout:
	free_sge_txq_uld(adap, txq_info);
	return err;
}
#endif

static void
release_sge_txq_uld(struct adapter *adap, unsigned int uld_type)
{
	struct sge_uld_txq_info *txq_info = NULL;
	int tx_uld_type = TX_ULD(uld_type);

	txq_info = adap->sge.uld_txq_info[tx_uld_type];

	if (txq_info && atomic_dec_and_test(&txq_info->users)) {
		free_sge_txq_uld(adap, txq_info);
		kfree(txq_info->uldtxq);
		kfree(txq_info);
		adap->sge.uld_txq_info[tx_uld_type] = NULL;
	}
}

#if 0
static int
setup_sge_txq_uld(struct adapter *adap, unsigned int uld_type,
		  const struct cxgb4_uld_info *uld_info)
{
	struct sge_uld_txq_info *txq_info = NULL;
	int tx_uld_type, i;

	tx_uld_type = TX_ULD(uld_type);
	txq_info = adap->sge.uld_txq_info[tx_uld_type];

	if ((tx_uld_type == CXGB4_TX_OFLD) && txq_info &&
	    (atomic_inc_return(&txq_info->users) > 1))
		return 0;

	txq_info = kzalloc_obj(*txq_info);
	if (!txq_info)
		return -ENOMEM;
	if (uld_type == CXGB4_ULD_CRYPTO) {
		i = min_t(int, adap->uld_inst.vres.ncrypto_fc,
			  num_online_cpus());
		txq_info->ntxq = rounddown(i, adap->params.nports);
		if (txq_info->ntxq <= 0) {
			dev_warn(adap->pdev_dev, "Crypto Tx Queues can't be zero\n");
			kfree(txq_info);
			return -EINVAL;
		}

	} else {
		i = min_t(int, uld_info->ntxq, num_online_cpus());
		txq_info->ntxq = roundup(i, adap->params.nports);
	}
	txq_info->uldtxq = kzalloc_objs(struct sge_uld_txq, txq_info->ntxq);
	if (!txq_info->uldtxq) {
		kfree(txq_info);
		return -ENOMEM;
	}

	if (alloc_sge_txq_uld(adap, txq_info, tx_uld_type)) {
		kfree(txq_info->uldtxq);
		kfree(txq_info);
		return -ENOMEM;
	}

	atomic_inc(&txq_info->users);
	adap->sge.uld_txq_info[tx_uld_type] = txq_info;
	return 0;
}
#endif

static void uld_queue_init(struct adapter *adap, unsigned int uld_type,
			   struct cxgb4_lld_info *lli)
{
	struct sge_uld_rxq_info *rxq_info = adap->sge.uld_rxq_info[uld_type];
	int tx_uld_type = TX_ULD(uld_type);
	struct sge_uld_txq_info *txq_info = adap->sge.uld_txq_info[tx_uld_type];

	lli->rxq_ids = rxq_info->rspq_id;
	lli->nrxq = rxq_info->nrxq;
	lli->ciq_ids = rxq_info->rspq_id + rxq_info->nrxq;
	lli->nciq = rxq_info->nciq;
	lli->ntxq = txq_info->ntxq;
}

int t4_uld_mem_alloc(struct adapter *adap)
{
	struct sge *s = &adap->sge;

	adap->uld = kzalloc_objs(*adap->uld, CXGB4_ULD_TYPE_MAX);
	if (!adap->uld)
		return -ENOMEM;

	s->uld_rxq_info = kzalloc_objs(struct sge_uld_rxq_info *, CXGB4_ULD_TYPE_MAX);
	if (!s->uld_rxq_info)
		goto err_uld;

	s->uld_txq_info = kzalloc_objs(struct sge_uld_txq_info *, CXGB4_TX_MAX);
	if (!s->uld_txq_info)
		goto err_uld_rx;
	return 0;

err_uld_rx:
	kfree(s->uld_rxq_info);
err_uld:
	kfree(adap->uld);
	return -ENOMEM;
}

void t4_uld_mem_free(struct adapter *adap)
{
	struct sge *s = &adap->sge;

	kfree(s->uld_txq_info);
	kfree(s->uld_rxq_info);
	kfree(adap->uld);
}

/* This function should be called with uld_mutex taken. */
static void cxgb4_shutdown_uld_adapter(struct adapter *adap, enum cxgb4_uld_type type)
{
	if (adap->uld[type].handle) {
		adap->uld[type].handle = NULL;
		adap->uld[type].add = NULL;
		release_sge_txq_uld(adap, type);

		if (adap->flags & CXGB4_FULL_INIT_DONE)
			quiesce_rx_uld(adap, type);

		if (adap->flags & CXGB4_USING_MSIX)
			free_msix_queue_irqs_uld(adap, type);

		free_sge_queues_uld(adap, type);
		free_queues_uld(adap, type);
	}
}

void t4_uld_clean_up(struct adapter *adap)
{
	unsigned int i;

	if (!is_uld(adap))
		return;

	mutex_lock(&uld_mutex);
	for (i = 0; i < CXGB4_ULD_TYPE_MAX; i++) {
		if (!adap->uld_handle[i])
			continue;

		cxgb4_shutdown_uld_adapter(adap, i);
	}
	mutex_unlock(&uld_mutex);
}

static void uld_init(struct adapter *adap, struct cxgb4_lld_info *lld, unsigned int uld)
{
	unsigned short i;
	struct sge_uld_rxq_info *rxq_info = adap->sge.uld_rxq_info[uld];

	lld->pdev = adap->pdev;
	lld->pf = adap->pf;
	lld->l2t = adap->l2t;
// __SS__	lld->tids = &adap->tids;
	lld->uld_tids.atids.start = adap->tidinfo.atids.start;
	lld->uld_tids.atids.size = adap->tidinfo.atids.size;
	lld->ports = adap->port;
	lld->vr = &adap->uld_inst.vres;
	lld->mtus = adap->params.mtus;
	if (uld == CXGB4_ULD_RDMA) {
		lld->rxq_ids = rxq_info->rspq_id;
		lld->ciq_ids = rxq_info->rspq_id + rxq_info->nrxq;
		lld->nrxq = rxq_info->nrxq;
		lld->nciq = rxq_info->nciq;
		lld->ctrlq_start = CXGB4_ULD_CTRLQ_INDEX_RDMA;
	}
	lld->nchan = adap->params.nports;
	lld->nports = adap->params.nports;
	lld->wr_cred = adap->params.ofldq_wr_cred;
// __SS__	lld->ulp_crypto = adap->params.crypto;
// __SS__	lld->iscsi_iolen = MAXRXDATA_G(t4_read_reg(adap, TP_PARA_REG2_A));
	lld->iscsi_tagmask = t4_read_reg(adap, ULP_RX_ISCSI_TAGMASK_A);
	lld->iscsi_pgsz_order = t4_read_reg(adap, ULP_RX_ISCSI_PSZ_A);
//__SS__	lld->iscsi_ppm = &adap->uld_inst.iscsi_ppm;
//__SS__	lld->adapter_type = adap->params.chip;

	if (CHELSIO_CHIP_VERSION(adap->params.chip) >= CHELSIO_T6) {
		u32 val = t4_read_reg(adap, ULP_RX_MISC_FEATURE_ENABLE_A);
		lld->iscsi_all_cmp_mode = !!(val & ISCSI_ALL_CMP_MODE_F);
	}

	if (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T6) {
		lld->iscsi_llimit = t4_read_reg(adap, ULP_RX_ISCSI_LLIMIT_A);
	} else {
		lld->iscsi_llimit = t4_read_reg(adap, ULP_RX_ISCSI_LLIMIT_A) << 4;

		if (!is_t7(adap->params.chip)) {
			u32 val = t4_read_reg(adap, ULP_RX_CTL1_A);
			lld->iscsi_non_ddp_bit = !!(val & ISCSI_CTL2_F);

			val = t4_read_reg(adap, SGE_CONTROL2_A);
			lld->cpl_iscsi_data_iqe = !!(val & RXCPLMODE_ISCSI_F);
			lld->cpl_nvmt_data_iqe = !!(val & RXCPLMODE_NVMT_F);
		}
	}

	lld->max_pdu_size = MAXRXDATA_G(t4_read_reg(adap, TP_PARA_REG2_A));
	lld->cnvme_ddp = &adap->uld_inst.cnvme_ddp;
	lld->rdma_resource = &adap->uld_inst.rdma_resource;
	lld->cclk_ps = 1000000000 / adap->params.vpd.cclk;
	lld->udb_density = 1 << adap->params.sge.eq_qpp;
	lld->ucq_density = 1 << adap->params.sge.iq_qpp;
	lld->sge_host_page_size = 1 << (adap->params.sge.hps + 10);
	lld->filt_mode = adap->params.tp.vlan_pri_map;
	for (i = 0; i < NCHAN; i++)
		lld->tx_modq[i] = adap->params.tp.tx_modq[i];
	lld->db_reg = adap->regs + MYPF_REG(SGE_PF_KDOORBELL_A);
	lld->gts_reg = adap->regs + MYPF_REG(SGE_PF_GTS_A);

	lld->fw_vers = adap->params.fw_vers;
	lld->dbfifo_int_thresh = LP_INT_THRESH_G(t4_read_reg(adap,
				SGE_DBFIFO_STATUS_A));
	lld->sge_ingpadboundary = adap->sge.fl_align;
	lld->sge_pktshift = adap->sge.pktshift;
	lld->sge_egrstatuspagesize = adap->sge.stat_len;
	lld->enable_fw_ofld_conn = adap->flags & CXGB4_FW_OFLD_CONN;
	lld->max_ordird_qp = adap->params.max_ordird_qp;
	lld->max_ird_adapter = adap->params.max_ird_adapter;
	lld->ulptx_memwrite_dsgl = adap->params.ulptx_memwrite_dsgl;
	lld->dev_512sgl_mr = adap->params.dev_512sgl_mr;
	lld->ulp_crypto = adap->params.crypto;
	lld->nodeid = dev_to_node(adap->pdev_dev);
	lld->fr_nsmr_tpte_wr_support = adap->params.fr_nsmr_tpte_wr_support;
	lld->write_w_imm_support = adap->params.write_w_imm_support;
	lld->relaxed_ordering = cxgb4_pcie_relaxed_ordering_enabled(adap);
	lld->write_cmpl_support = adap->params.write_cmpl_support;
	lld->neq = adap->params.pfres.neq;
	lld->sendpath_enabled = cxgb4_uld_sendpath_enabled(adap);
	lld->num_up_cores = adap->params.num_up_cores;
	lld->tid_qid_sel_mask = adap->params.tid_qid_sel_mask;
	lld->tid_qid_sel_shift = adap->params.tid_qid_sel_shift;
}

int uld_attach(struct adapter *adap, unsigned int uld)
{
	struct cxgb4_lld_info lli = {0};
	void *handle;

	uld_init(adap, &lli, uld);
	uld_queue_init(adap, uld, &lli);

	handle = adap->uld[uld].add(&lli);
	if (IS_ERR(handle)) {
		dev_warn(adap->pdev_dev,
			 "could not attach to the %s driver, error %ld\n",
			 adap->uld[uld].name, PTR_ERR(handle));
		return PTR_ERR(handle);
	}

	adap->uld[uld].handle = handle;
	t4_register_netevent_notifier();

	if (adap->flags & CXGB4_FULL_INIT_DONE)
		adap->uld[uld].state_change(handle, CXGB4_STATE_UP);

	return 0;
}

#if IS_ENABLED(CONFIG_CHELSIO_TLS_DEVICE)

#if 0
// __SS__ commenting for now
static bool cxgb4_uld_in_use(struct adapter *adap)
{
	const struct tid_info *t = &adap->tids;

	return (atomic_read(&t->conns_in_use) || t->stids_in_use);
}
#endif

/* cxgb4_set_ktls_feature: request FW to enable/disable ktls settings.
 * @adap: adapter info
 * @enable: 1 to enable / 0 to disable ktls settings.
 */
int cxgb4_set_ktls_feature(struct adapter *adap, bool enable)
{
	int ret = 0;
	u32 params =
		FW_PARAMS_MNEM_V(FW_PARAMS_MNEM_DEV) |
		FW_PARAMS_PARAM_X_V(FW_PARAMS_PARAM_DEV_KTLS_HW) |
		FW_PARAMS_PARAM_Y_V(enable) |
		FW_PARAMS_PARAM_Z_V(FW_PARAMS_PARAM_DEV_KTLS_HW_USER_ENABLE);

	if (enable) {
		if (!refcount_read(&adap->chcr_ktls.ktls_refcount)) {
			/* At this moment if ULD connection are up means, other
			 * ULD is/are already active, return failure.
			 */
			ret = t4_set_params(adap, adap->mbox, adap->pf,
					    0, 1, &params, &params);
			if (ret)
				return ret;
			refcount_set(&adap->chcr_ktls.ktls_refcount, 1);
			pr_debug("kTLS has been enabled. Restrictions placed on ULD support\n");
		} else {
			/* ktls settings already up, just increment refcount. */
			refcount_inc(&adap->chcr_ktls.ktls_refcount);
		}
	} else {
		/* return failure if refcount is already 0. */
		if (!refcount_read(&adap->chcr_ktls.ktls_refcount))
			return -EINVAL;
		/* decrement refcount and test, if 0, disable ktls feature,
		 * else return command success.
		 */
		if (refcount_dec_and_test(&adap->chcr_ktls.ktls_refcount)) {
			ret = t4_set_params(adap, adap->mbox, adap->pf,
					    0, 1, &params, &params);
			if (ret)
				return ret;
			pr_debug("kTLS is disabled. Restrictions on ULD support removed\n");
		}
	}

	return ret;
}
#endif

void cxgb4_uld_alloc_resources(struct adapter *adap,
			       enum cxgb4_uld_type type,
			       const struct cxgb4_uld_info *p)
{
	int ret = 0;

	if ((type == CXGB4_ULD_CRYPTO && !is_pci_uld(adap)) ||
	    (type != CXGB4_ULD_CRYPTO && !is_offload(adap)))
		return;
	if (type == CXGB4_ULD_ISCSIT && is_t4(adap->params.chip))
		return;
	ret = cfg_queues_uld(adap, type, p);
	if (ret)
		goto out;
	ret = setup_sge_queues_uld(adap, type, p->lro);
	if (ret)
		goto free_queues;
	if (adap->flags & CXGB4_USING_MSIX) {
		ret = request_msix_queue_irqs_uld(adap, type);
		if (ret)
			goto free_rxq;
	}
	if (adap->flags & CXGB4_FULL_INIT_DONE)
		enable_rx_uld(adap, type);
	return;
free_rxq:
	free_sge_queues_uld(adap, type);
free_queues:
	free_queues_uld(adap, type);
out:
	dev_warn(adap->pdev_dev,
		 "ULD registration failed for uld type %d\n", type);
}

/* cxgb4_register_uld - register an upper-layer driver
 * @type: the ULD type
 * @p: the ULD methods
 *
 * Registers an upper-layer driver with this driver and notifies the ULD
 * about any presently available devices that support its type.
 */
void cxgb4_register_uld(enum cxgb4_uld_type type,
			const struct cxgb4_uld_info *p)
{
	struct adapter *adap;

	if (type >= CXGB4_ULD_TYPE_MAX)
		return;

	if (!cxgb4_modparam_enable_ulds_supported(type)) {
		pr_err("ULD %s is explicitly disabled by enable_ulds modparam: 0x%x\n",
				cxgb4_uld_type_to_name(type),
				cxgb4_modparam_enable_ulds());
		return;
	}

	mutex_lock(&uld_mutex);
	if (cxgb4_ulds[type].add) {
		goto out;
	}
	cxgb4_ulds[type] = *p;
	list_for_each_entry(adap, &adapter_list, list_node) {
		cxgb4_uld_alloc_resources(adap, type, p);
		uld_attach(adap, type);
	}
	mutex_unlock(&uld_mutex);

out:
	return;
}
EXPORT_SYMBOL(cxgb4_register_uld);

/**
 *	cxgb4_unregister_uld - unregister an upper-layer driver
 *	@type: the ULD type
 *
 *	Unregisters an existing upper-layer driver.
 */
int cxgb4_unregister_uld(enum cxgb4_uld_type type)
{
	struct adapter *adap;

	if (type >= CXGB4_ULD_TYPE_MAX)
		return -EINVAL;

	mutex_lock(&uld_mutex);
	list_for_each_entry(adap, &adapter_list, list_node) {
		mutex_lock(&adap->uld_inst.uld_mutex);
		cxgb4_shutdown_uld_adapter(adap, type);
		adap->uld_handle[type] = NULL;
		mutex_unlock(&adap->uld_inst.uld_mutex);
	}
	cxgb4_ulds[type].add = NULL;
	mutex_unlock(&uld_mutex);

	return 0;
}
EXPORT_SYMBOL(cxgb4_unregister_uld);
