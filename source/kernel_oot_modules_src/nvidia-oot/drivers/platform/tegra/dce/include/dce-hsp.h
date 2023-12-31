/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019-2023, NVIDIA CORPORATION.  All rights reserved.
 */

#ifndef DCE_HSP_H
#define DCE_HSP_H

#include <linux/types.h>

struct tegra_dce;

/**
 * DCE HSP Shared Semaphore Utility functions. Description
 * can be found with function definitions.
 */
u32 dce_ss_get_state(struct tegra_dce *d, u8 id);
void dce_ss_set(struct tegra_dce *d, u8 bpos, u8 id);
void dce_ss_clear(struct tegra_dce *d, u8 bpos, u8 id);

/**
 * DCE HSP Shared Mailbox Utility functions.  Description
 * can be found with function definitions.
 */
void dce_smb_set(struct tegra_dce *d, u32 val, u8 id);
void dce_smb_set_full_ie(struct tegra_dce *d, bool en, u8 id);
u32 dce_smb_read_full_ie(struct tegra_dce *d, u8 id);
void dce_smb_set_empty_ie(struct tegra_dce *d, bool en, u8 id);
u32 dce_smb_read(struct tegra_dce *d, u8 id);
u32 dce_hsp_ie_read(struct tegra_dce *d, u8 id);
void dce_hsp_ie_write(struct tegra_dce *d, u32 val, u8 id);
u32 dce_hsp_ir_read(struct tegra_dce *d);

#endif
