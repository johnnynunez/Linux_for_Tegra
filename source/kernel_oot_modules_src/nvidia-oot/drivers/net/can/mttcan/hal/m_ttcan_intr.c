/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "../include/m_ttcan.h"

void ttcan_clear_intr(struct ttcan_controller *ttcan)
{
	ttcan_write32(ttcan, ADR_MTTCAN_IR, 0xFFFFFFFF);
}

void ttcan_clear_tt_intr(struct ttcan_controller *ttcan)
{
	ttcan_write32(ttcan, ADR_MTTCAN_TTIR, 0xFFFFFFFF);
}

u32 ttcan_read_ir(struct ttcan_controller *ttcan)
{
	return ttcan_read32(ttcan, ADR_MTTCAN_IR);
}

void ttcan_ir_write(struct ttcan_controller *ttcan, u32 value)
{
	return ttcan_write32(ttcan, ADR_MTTCAN_IR, value);
}

void ttcan_ttir_write(struct ttcan_controller *ttcan, u32 value)
{
	return ttcan_write32(ttcan, ADR_MTTCAN_TTIR, value);
}

u32 ttcan_read_ttir(struct ttcan_controller *ttcan)
{
	return ttcan_read32(ttcan, ADR_MTTCAN_TTIR);
}

void ttcan_ier_write(struct ttcan_controller *ttcan, u32 val)
{
	ttcan_write32(ttcan, ADR_MTTCAN_IE, val);
}

void ttcan_ttier_write(struct ttcan_controller *ttcan, u32 val)
{
	ttcan_write32(ttcan, ADR_MTTCAN_TTIE, val);
}

void ttcan_set_intrpts(struct ttcan_controller *ttcan, int enable)
{
	if (enable) {
		ttcan_write32(ttcan, ADR_MTTCAN_IE, ttcan->intr_enable_reg);
		ttcan_write32(ttcan, ADR_MTTCAN_TTIE,
			ttcan->intr_tt_enable_reg);
		ttcan_write32(ttcan, ADR_MTTCAN_ILE, 0x1);
	} else {
		ttcan_write32(ttcan, ADR_MTTCAN_IE, 0);
		ttcan_write32(ttcan, ADR_MTTCAN_TTIE, 0);
		ttcan_write32(ttcan, ADR_MTTCAN_ILE, 0x0);
	}
	pr_debug("%s:%s intr %x\n", __func__, enable ? "enabled" : "disabled",
			ttcan->intr_enable_reg);
}
