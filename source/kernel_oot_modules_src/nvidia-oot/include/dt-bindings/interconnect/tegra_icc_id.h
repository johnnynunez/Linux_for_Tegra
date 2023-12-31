/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2020-2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef _DT_BINDINGS_TEGRA_ICC_ID_H
#define _DT_BINDINGS_TEGRA_ICC_ID_H

/* ICC master node */
#define TEGRA_ICC_PRIMARY			0
#define TEGRA_ICC_DEBUG				1
#define TEGRA_ICC_CPU_CLUSTER0			2
#define TEGRA_ICC_CPU_CLUSTER1			3
#define TEGRA_ICC_CPU_CLUSTER2			4
#define TEGRA_ICC_GPU				5
#define TEGRA_ICC_CACTMON			6
#define TEGRA_ICC_DISPLAY			7
#define TEGRA_ICC_VI				8
#define TEGRA_ICC_EQOS				9
#define TEGRA_ICC_PCIE_0			10
#define TEGRA_ICC_PCIE_1			11
#define TEGRA_ICC_PCIE_2			12
#define TEGRA_ICC_PCIE_3			13
#define TEGRA_ICC_PCIE_4			14
#define TEGRA_ICC_PCIE_5			15
#define TEGRA_ICC_PCIE_6			16
#define TEGRA_ICC_PCIE_7			17
#define TEGRA_ICC_PCIE_8			18
#define TEGRA_ICC_PCIE_9			19
#define TEGRA_ICC_PCIE_10			20
#define TEGRA_ICC_DLA_0				21
#define TEGRA_ICC_DLA_1				22
#define TEGRA_ICC_SDMMC_1			23
#define TEGRA_ICC_SDMMC_2			24
#define TEGRA_ICC_SDMMC_3			25
#define TEGRA_ICC_SDMMC_4			26
#define TEGRA_ICC_NVDEC				27
#define TEGRA_ICC_NVENC				28
#define TEGRA_ICC_NVJPG_0			29
#define TEGRA_ICC_NVJPG_1			30
#define TEGRA_ICC_OFAA				31
#define TEGRA_ICC_XUSB_HOST			32
#define TEGRA_ICC_XUSB_DEV			33
#define TEGRA_ICC_TSEC				34
#define TEGRA_ICC_VIC				35
#define TEGRA_ICC_APE				36
#define TEGRA_ICC_APEDMA			37
#define TEGRA_ICC_SE				38
#define TEGRA_ICC_ISP				39
#define TEGRA_ICC_HDA				40
#define TEGRA_ICC_VIFAL				41
#define TEGRA_ICC_VI2FAL			42
#define TEGRA_ICC_VI2				43
#define TEGRA_ICC_RCE				44
#define TEGRA_ICC_PVA				45
#define TEGRA_ICC_NVPMODEL			46

/* remove later */
#define NV_NVDISPLAYR2MC_SR_ID			TEGRA_ICC_DISPLAY
#define TEGRA_ICC_MASTER			TEGRA_ICC_PRIMARY

#endif /* _DT_BINDINGS_TEGRA_ICC_ID_H */
