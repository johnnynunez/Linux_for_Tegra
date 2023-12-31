/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Tegra 19x CSI register offsets
 *
 * Copyright (c) 2017-2022, NVIDIA CORPORATION. All rights reserved.
 */


#ifndef __CSI5_REGISTERS_H__
#define __CSI5_REGISTERS_H__

#define CSI5_BASE_ADDRESS		0x011000
#define CSI5_PHY_OFFSET			0x010000

#define CSI5_TEGRA_CSI_STREAM_0_BASE	0x10000
#define CSI5_TEGRA_CSI_STREAM_2_BASE	0x20000
#define CSI5_TEGRA_CSI_STREAM_4_BASE	0x30000

#define CSI5_NVCSI_CIL_A_SW_RESET	0x24
#define CSI5_NVCSI_CIL_B_SW_RESET	0xb0
#define CSI5_SW_RESET1_EN		(0x1 << 1)
#define CSI5_SW_RESET0_EN		(0x1 << 0)

#define CSI5_E_INPUT_LP_IO1_SHIFT	22
#define CSI5_E_INPUT_LP_IO0_SHIFT	21
#define CSI5_E_INPUT_LP_CLK_SHIFT	20
#define CSI5_E_INPUT_LP_IO1		(0x1 << 22)
#define CSI5_E_INPUT_LP_IO0		(0x1 << 21)
#define CSI5_E_INPUT_LP_CLK		(0x1 << 20)
#define CSI5_PD_CLK			(0x1 << 18)
#define CSI5_PD_IO1			(0x1 << 17)
#define CSI5_PD_IO0			(0x1 << 16)
#define CSI5_PD_CLK_SHIFT		18
#define CSI5_PD_IO1_SHIFT		17
#define CSI5_PD_IO0_SHIFT		16

/* MIPICAL */
#define	CSI5_NVCSI_CIL_A_BASE		0x24
#define CSI5_NVCSI_CIL_B_BASE		0xb0
#define CSI5_PAD_CONFIG_0		0x8

#endif /* __CSI5_REGISTERS_H__ */
