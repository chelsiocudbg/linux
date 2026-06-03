/*
 * This file is part of the Chelsio T4/T5/T6/T7 Ethernet driver for Linux.
 *
 * Copyright (C) 2023 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGB4_PCI_H__
#define __CXGB4_PCI_H__

#define CXGB4_UNIFIED_PF 0x4

int cxgb4_pci_resource_init(struct adapter *adap);
void cxgb4_pci_resource_free(struct adapter *adap);
int cxgb4_pci_chip_init(struct adapter *adap);
void cxgb4_pci_chip_free(struct adapter *adap);
void cxgb4_pci_setup_memwin(struct adapter *adap);
void cxgb4_pci_setup_memwin_rdma(struct adapter *adap);
void cxgb4_pci_fw_free(struct adapter *adap);
int cxgb4_pci_fw_init(struct adapter *adap, enum dev_state *state);
int cxgb4_pci_device_id(struct adapter *adap);
bool cxgb4_pci_relaxed_ordering_enabled(struct adapter *adap);
bool cxgb4_pci_msix_enabled(struct adapter *adap);
bool cxgb4_pci_msi_enabled(struct adapter *adap);
int cxgb4_pci_read_config_word(struct adapter *adap, int where, u16 *val);
int cxgb4_pci_write_config_word(struct adapter *adap, int where, u16 val);
ssize_t cxgb4_pci_read_vpd(struct adapter *adap, loff_t pos, size_t count,
                          void *buf);
ssize_t cxgb4_pci_write_vpd(struct adapter *adap, loff_t pos, size_t count,
                           const void *buf);
int cxgb4_pci_memory_rw(struct adapter *adap, int win, u64 addr, u64 len,
                       void *buf, int dir);
#if !defined(CHELSIO_T4_DIAGS) && defined(CONFIG_PCI_IOV)
int cxgb4_pci_iov_configure(struct adapter *adap, int num_vfs);
#endif

int cxgb4_pci_driver_register(void);
void cxgb4_pci_driver_unregister(void);
#endif /* __CXGB4_PCI_H__ */
