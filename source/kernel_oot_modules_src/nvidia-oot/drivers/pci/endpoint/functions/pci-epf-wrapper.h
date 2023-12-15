/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * PCIe EDMA Framework
 *
 * Copyright (C) 2022 NVIDIA Corporation. All rights reserved.
 */

#ifndef PCI_EPF_WRAPPER_H
#define PCI_EPF_WRAPPER_H

#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
#define lpci_epf_free_space(A, B, C)	pci_epf_free_space(A, B, C, PRIMARY_INTERFACE)
#define lpci_epf_alloc_space(A, B, C, D)	pci_epf_alloc_space(A, B, C, D, PRIMARY_INTERFACE)
#else
#define lpci_epf_free_space(A, B, C)	pci_epf_free_space(A, B, C)
#define lpci_epf_alloc_space(A, B, C, D)	pci_epf_alloc_space(A, B, C, D)
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5, 14, 0))
#define lpci_epc_write_header(A, B, C)	pci_epc_write_header(A, B, 0, C)
#define lpci_epc_raise_irq(A, B, C, D)	pci_epc_raise_irq(A, B, 0, C, D)
#define lpci_epc_clear_bar(A, B, C)	pci_epc_clear_bar(A, B, 0, C)
#define lpci_epc_set_msi(A, B, C)	pci_epc_set_msi(A, B, 0, C)
#define lpci_epc_set_bar(A, B, C)	pci_epc_set_bar(A, B, 0, C)
#define lpci_epc_unmap_addr(A, B, C)	pci_epc_unmap_addr(A, B, 0, C)
#else
#define lpci_epc_write_header(A, B, C)	pci_epc_write_header(A, B, C)
#define lpci_epc_raise_irq(A, B, C, D)	pci_epc_raise_irq(A, B, C, D)
#define lpci_epc_clear_bar(A, B, C)	pci_epc_clear_bar(A, B, C)
#define lpci_epc_set_msi(A, B, C)	pci_epc_set_msi(A, B, C)
#define lpci_epc_set_bar(A, B, C)	pci_epc_set_bar(A, B, C)
#define lpci_epc_unmap_addr(A, B, C)	pci_epc_unmap_addr(A, B, C)
#endif /* LINUX_VERSION_CODE */

#endif /* PCI_EPF_WRAPPER_H */
