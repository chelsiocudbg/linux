/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2026 Chelsio Communications.  All rights reserved.
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
int cxgb4_pci_fw_init(struct adapter *adap, enum dev_state *state);
bool cxgb4_pci_msix_enabled(struct adapter *adap);
bool cxgb4_pci_msi_enabled(struct adapter *adap);

int cxgb4_pci_driver_register(void);
void cxgb4_pci_driver_unregister(void);
#endif /* __CXGB4_PCI_H__ */
