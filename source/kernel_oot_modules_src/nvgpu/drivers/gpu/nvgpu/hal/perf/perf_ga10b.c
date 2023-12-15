// SPDX-License-Identifier: MIT
/*
 * SPDX-FileCopyrightText: Copyright (c) 2020-2023, NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <nvgpu/io.h>
#include <nvgpu/mm.h>
#include <nvgpu/fbp.h>
#include <nvgpu/gr/gr_utils.h>
#include <nvgpu/gr/config.h>
#include <nvgpu/bug.h>
#include <nvgpu/gk20a.h>
#include <nvgpu/utils.h>

#include "perf_ga10b.h"

#include <nvgpu/hw/ga10b/hw_perf_ga10b.h>

#define PMM_ROUTER_OFFSET	0x200U

/*
 * Only 1 instance is supported for pmasys_channel_* registers in ga10b
 */
const u32 pmasys_channel_instance_max_size = 0x1U;
const u32 inst_zero = 0U;

static const u32 hwpm_sys_perfmon_regs[] =
{
	/* This list is autogenerated. Do not edit. */
	0x00260000,
	0x00260004,
	0x00260008,
	0x0026000c,
	0x00260010,
	0x00260014,
	0x00260020,
	0x00260024,
	0x00260028,
	0x0026002c,
	0x00260030,
	0x00260034,
	0x00260040,
	0x00260044,
	0x00260048,
	0x0026004c,
	0x00260050,
	0x00260054,
	0x00260058,
	0x0026005c,
	0x00260060,
	0x00260064,
	0x00260068,
	0x0026006c,
	0x00260070,
	0x00260074,
	0x00260078,
	0x0026007c,
	0x00260080,
	0x00260084,
	0x00260088,
	0x0026008c,
	0x00260090,
	0x00260098,
	0x0026009c,
	0x002600a0,
	0x002600a4,
	0x002600a8,
	0x002600ac,
	0x002600b0,
	0x002600b4,
	0x002600b8,
	0x002600bc,
	0x002600c0,
	0x002600c4,
	0x002600c8,
	0x002600cc,
	0x002600d0,
	0x002600d4,
	0x002600d8,
	0x002600dc,
	0x002600e0,
	0x002600e4,
	0x002600e8,
	0x002600ec,
	0x002600f8,
	0x002600fc,
	0x00260108,
	0x00260110,
	0x00260128,
	0x00260114,
	0x00260118,
	0x0026011c,
	0x00260124,
	0x00260130,
	0x00260100,
};

static const u32 hwpm_gpc_perfmon_regs[] =
{
	/* This list is autogenerated. Do not edit. */
	0x00278000,
	0x00278004,
	0x00278008,
	0x0027800c,
	0x00278010,
	0x00278014,
	0x00278020,
	0x00278024,
	0x00278028,
	0x0027802c,
	0x00278030,
	0x00278034,
	0x00278040,
	0x00278044,
	0x00278048,
	0x0027804c,
	0x00278050,
	0x00278054,
	0x00278058,
	0x0027805c,
	0x00278060,
	0x00278064,
	0x00278068,
	0x0027806c,
	0x00278070,
	0x00278074,
	0x00278078,
	0x0027807c,
	0x00278080,
	0x00278084,
	0x00278088,
	0x0027808c,
	0x00278090,
	0x00278098,
	0x0027809c,
	0x002780a0,
	0x002780a4,
	0x002780a8,
	0x002780ac,
	0x002780b0,
	0x002780b4,
	0x002780b8,
	0x002780bc,
	0x002780c0,
	0x002780c4,
	0x002780c8,
	0x002780cc,
	0x002780d0,
	0x002780d4,
	0x002780d8,
	0x002780dc,
	0x002780e0,
	0x002780e4,
	0x002780e8,
	0x002780ec,
	0x002780f8,
	0x002780fc,
	0x00278108,
	0x00278110,
	0x00278128,
	0x00278114,
	0x00278118,
	0x0027811c,
	0x00278124,
	0x00278130,
	0x00278100,
};

static const u32 hwpm_fbp_perfmon_regs[] =
{
	/* This list is autogenerated. Do not edit. */
	0x0027c000,
	0x0027c004,
	0x0027c008,
	0x0027c00c,
	0x0027c010,
	0x0027c014,
	0x0027c020,
	0x0027c024,
	0x0027c028,
	0x0027c02c,
	0x0027c030,
	0x0027c034,
	0x0027c040,
	0x0027c044,
	0x0027c048,
	0x0027c04c,
	0x0027c050,
	0x0027c054,
	0x0027c058,
	0x0027c05c,
	0x0027c060,
	0x0027c064,
	0x0027c068,
	0x0027c06c,
	0x0027c070,
	0x0027c074,
	0x0027c078,
	0x0027c07c,
	0x0027c080,
	0x0027c084,
	0x0027c088,
	0x0027c08c,
	0x0027c090,
	0x0027c098,
	0x0027c09c,
	0x0027c0a0,
	0x0027c0a4,
	0x0027c0a8,
	0x0027c0ac,
	0x0027c0b0,
	0x0027c0b4,
	0x0027c0b8,
	0x0027c0bc,
	0x0027c0c0,
	0x0027c0c4,
	0x0027c0c8,
	0x0027c0cc,
	0x0027c0d0,
	0x0027c0d4,
	0x0027c0d8,
	0x0027c0dc,
	0x0027c0e0,
	0x0027c0e4,
	0x0027c0e8,
	0x0027c0ec,
	0x0027c0f8,
	0x0027c0fc,
	0x0027c108,
	0x0027c110,
	0x0027c128,
	0x0027c114,
	0x0027c118,
	0x0027c11c,
	0x0027c124,
	0x0027c130,
	0x0027c100,
};

const u32 *ga10b_perf_get_hwpm_sys_perfmon_regs(u32 *count)
{
	*count = sizeof(hwpm_sys_perfmon_regs) / sizeof(hwpm_sys_perfmon_regs[0]);
	return hwpm_sys_perfmon_regs;
}

const u32 *ga10b_perf_get_hwpm_gpc_perfmon_regs(u32 *count)
{
	*count = sizeof(hwpm_gpc_perfmon_regs) / sizeof(hwpm_gpc_perfmon_regs[0]);
	return hwpm_gpc_perfmon_regs;
}

const u32 *ga10b_perf_get_hwpm_fbp_perfmon_regs(u32 *count)
{
	*count = sizeof(hwpm_fbp_perfmon_regs) / sizeof(hwpm_fbp_perfmon_regs[0]);
	return hwpm_fbp_perfmon_regs;
}

bool ga10b_perf_get_membuf_overflow_status(struct gk20a *g)
{
	const u32 st =
		perf_pmasys_channel_status_secure_membuf_status_overflowed_f();

	nvgpu_assert(perf_pmasys_channel_status_secure__size_1_v() ==
				pmasys_channel_instance_max_size);

	return st == (nvgpu_readl(g,
			perf_pmasys_channel_status_secure_r(inst_zero)) & st);
}

u32 ga10b_perf_get_membuf_pending_bytes(struct gk20a *g)
{
	nvgpu_assert(perf_pmasys_channel_mem_bytes__size_1_v() ==
				pmasys_channel_instance_max_size);

	return nvgpu_readl(g,
		perf_pmasys_channel_mem_bytes_r(inst_zero));
}

void ga10b_perf_set_membuf_handled_bytes(struct gk20a *g,
	u32 entries, u32 entry_size)
{
	nvgpu_assert(perf_pmasys_channel_mem_bump__size_1_v() ==
				pmasys_channel_instance_max_size);

	if (entries > 0U) {
		nvgpu_writel(g,
			perf_pmasys_channel_mem_bump_r(inst_zero),
			entries * entry_size);
	}
}

void ga10b_perf_membuf_reset_streaming(struct gk20a *g)
{
	u32 engine_status;
	u32 num_unread_bytes;
	u32 i;

	nvgpu_assert(perf_pmasys_channel_control_user__size_1_v() ==
				pmasys_channel_instance_max_size);
	nvgpu_assert(perf_pmasys_channel_mem_bytes__size_1_v() ==
				pmasys_channel_instance_max_size);
	nvgpu_assert(perf_pmasys_channel_mem_bump__size_1_v() ==
				pmasys_channel_instance_max_size);

	engine_status = nvgpu_readl(g, perf_pmasys_enginestatus_r());
	WARN_ON(0U ==
	       (engine_status & perf_pmasys_enginestatus_rbufempty_empty_f()));

	for (i = 0U; i < perf_pmasys_channel_control_user__size_1_v(); i++) {
		nvgpu_writel(g, perf_pmasys_channel_control_user_r(i),
		     perf_pmasys_channel_control_user_membuf_clear_status_doit_f());
	}

	for (i = 0U; i < perf_pmasys_channel_mem_bytes__size_1_v(); i++) {
		num_unread_bytes = nvgpu_readl(g,
					perf_pmasys_channel_mem_bytes_r(i));
		if (num_unread_bytes != 0U) {
			nvgpu_writel(g, perf_pmasys_channel_mem_bump_r(i),
					num_unread_bytes);
		}
	}
}

void ga10b_perf_enable_membuf(struct gk20a *g, u32 size, u64 buf_addr)
{
	u32 addr_lo;
	u32 addr_hi;
	u32 i;

	nvgpu_assert(perf_pmasys_channel_outbase__size_1_v() ==
				pmasys_channel_instance_max_size);
	nvgpu_assert(perf_pmasys_channel_outbaseupper__size_1_v() ==
				pmasys_channel_instance_max_size);
	nvgpu_assert(perf_pmasys_channel_outsize__size_1_v() ==
				pmasys_channel_instance_max_size);

	addr_lo = u64_lo32(buf_addr);
	addr_hi = u64_hi32(buf_addr);

	for (i = 0U; i < perf_pmasys_channel_outbase__size_1_v(); i++) {
		nvgpu_writel(g, perf_pmasys_channel_outbase_r(i), addr_lo);
	}

	for (i = 0U; i < perf_pmasys_channel_outbaseupper__size_1_v(); i++) {
		nvgpu_writel(g, perf_pmasys_channel_outbaseupper_r(i),
			perf_pmasys_channel_outbaseupper_ptr_f(addr_hi));
	}

	for (i = 0U; i < perf_pmasys_channel_outsize__size_1_v(); i++) {
		nvgpu_writel(g, perf_pmasys_channel_outsize_r(i), size);
	}
}

void ga10b_perf_disable_membuf(struct gk20a *g)
{
	u32 zero_value = 0U;
	u32 i;

	nvgpu_assert(perf_pmasys_channel_outbase__size_1_v() ==
				pmasys_channel_instance_max_size);
	nvgpu_assert(perf_pmasys_channel_outbaseupper__size_1_v() ==
				pmasys_channel_instance_max_size);
	nvgpu_assert(perf_pmasys_channel_outsize__size_1_v() ==
				pmasys_channel_instance_max_size);

	for (i = 0U; i < perf_pmasys_channel_outbase__size_1_v(); i++) {
		nvgpu_writel(g, perf_pmasys_channel_outbase_r(i), zero_value);
	}

	for (i = 0U; i < perf_pmasys_channel_outbaseupper__size_1_v(); i++) {
		nvgpu_writel(g, perf_pmasys_channel_outbaseupper_r(i),
			perf_pmasys_channel_outbaseupper_ptr_f(zero_value));
	}

	for (i = 0U; i < perf_pmasys_channel_outsize__size_1_v(); i++) {
		nvgpu_writel(g, perf_pmasys_channel_outsize_r(i), zero_value);
	}
}

void ga10b_perf_bind_mem_bytes_buffer_addr(struct gk20a *g, u64 buf_addr)
{
	u32 addr_lo;
	u32 i;

	nvgpu_assert(perf_pmasys_channel_mem_bytes_addr__size_1_v() ==
				pmasys_channel_instance_max_size);

	/*
	 * For mem bytes addr, the upper 8 bits of the 40bit VA is taken
	 * from perf_pmasys_channel_outbaseupper_r(), so only consider
	 * the lower 32bits in the buf_addr and discard the rest.
	 */
	buf_addr = u64_lo32(buf_addr);
	buf_addr = buf_addr >> perf_pmasys_channel_mem_bytes_addr_ptr_b();
	addr_lo = nvgpu_safe_cast_u64_to_u32(buf_addr);

	for (i = 0U; i < perf_pmasys_channel_mem_bytes_addr__size_1_v(); i++) {
		nvgpu_writel(g, perf_pmasys_channel_mem_bytes_addr_r(i),
				perf_pmasys_channel_mem_bytes_addr_ptr_f(addr_lo));
	}
}

void ga10b_perf_init_inst_block(struct gk20a *g, struct nvgpu_mem *inst_block)
{
	u32 inst_block_ptr;
	u32 i;

	nvgpu_assert(perf_pmasys_channel_mem_block__size_1_v() ==
				pmasys_channel_instance_max_size);

	for (i = 0U; i < perf_pmasys_channel_mem_block__size_1_v(); i++) {
		inst_block_ptr = nvgpu_inst_block_ptr(g, inst_block);

		nvgpu_writel(g, perf_pmasys_channel_mem_block_r(i),
		     perf_pmasys_channel_mem_block_base_f(inst_block_ptr) |
		     perf_pmasys_channel_mem_block_valid_true_f() |
			nvgpu_aperture_mask(g, inst_block,
			     perf_pmasys_channel_mem_block_target_sys_ncoh_f(),
			     perf_pmasys_channel_mem_block_target_sys_coh_f(),
			     perf_pmasys_channel_mem_block_target_lfb_f()));
	}
}

void ga10b_perf_deinit_inst_block(struct gk20a *g)
{
	int zero_value = 0;
	u32 i;

	nvgpu_assert(perf_pmasys_channel_mem_block__size_1_v() ==
				pmasys_channel_instance_max_size);

	for (i = 0U; i < perf_pmasys_channel_mem_block__size_1_v(); i++) {
		nvgpu_writel(g, perf_pmasys_channel_mem_block_r(i),
			perf_pmasys_channel_mem_block_base_f(zero_value) |
			perf_pmasys_channel_mem_block_valid_false_f() |
			perf_pmasys_channel_mem_block_target_f(zero_value));
	}
}

u32 ga10b_perf_get_pmmsys_per_chiplet_offset(void)
{
	/*
	 * No register to find the offset of pmmsys register.
	 * Difference of pmmsys register address ranges plus 1 will provide
	 * the offset
	 */
	u32 reg_offset = 1U;

	return (perf_pmmsys_extent_v() - perf_pmmsys_base_v() + reg_offset);
}

u32 ga10b_perf_get_pmmgpc_per_chiplet_offset(void)
{
	/*
	 * No register to find the offset of pmmgpc register.
	 * Difference of pmmgpc register address ranges plus 1 will provide
	 * the offset
	 */
	u32 reg_offset = 1U;

	return (perf_pmmgpc_extent_v() - perf_pmmgpc_base_v() + reg_offset);
}

u32 ga10b_perf_get_pmmgpcrouter_per_chiplet_offset(void)
{
	/*
	 * No register to find the offset of pmmgpc register.
	 * Difference of pmmgpc register address ranges plus 1 will provide
	 * the offset
	 */
	u32 reg_offset = 1U;

	return (perf_pmmgpcrouter_extent_v() - perf_pmmgpcrouter_base_v() + reg_offset);
}

u32 ga10b_perf_get_pmmfbp_per_chiplet_offset(void)
{
	/*
	 * No register to find the offset of pmmfbp register.
	 * Difference of pmmfbp register address ranges plus 1 will provide
	 * the offset
	 */
	u32 reg_offset = 1U;

	return (perf_pmmfbp_extent_v() - perf_pmmfbp_base_v() + reg_offset);
}

u32 ga10b_perf_get_pmmfbprouter_per_chiplet_offset(void)
{
	/*
	 * No register to find the offset of pmmgpc register.
	 * Difference of pmmgpc register address ranges plus 1 will provide
	 * the offset
	 */
	u32 reg_offset = 1U;

	return (perf_pmmfbprouter_extent_v() - perf_pmmfbprouter_base_v() + reg_offset);
}

u32 ga10b_get_hwpm_fbp_perfmon_regs_base(struct gk20a *g)
{
	(void)g;
	return perf_pmmfbp_base_v();
}

u32 ga10b_get_hwpm_gpc_perfmon_regs_base(struct gk20a *g)
{
	(void)g;
	return perf_pmmgpc_base_v();
}

void ga10b_perf_get_num_hwpm_perfmon(struct gk20a *g, u32 *num_sys_perfmon,
				u32 *num_fbp_perfmon, u32 *num_gpc_perfmon)
{
	int err;
	u32 buf_offset_lo, buf_offset_addr, num_offsets;
	u32 perfmon_index = 0U;
	u32 max_offsets = 1U;

	for (perfmon_index = 0U; perfmon_index <
			perf_pmmsys_engine_sel__size_1_v();
			perfmon_index++) {
		err = g->ops.gr.get_pm_ctx_buffer_offsets(g,
				perf_pmmsys_engine_sel_r(perfmon_index),
				max_offsets,
				&buf_offset_lo,
				&buf_offset_addr,
				&num_offsets);
		if (err != 0U) {
			break;
		}
	}
	*num_sys_perfmon = perfmon_index;

	for (perfmon_index = 0U; perfmon_index <
			perf_pmmfbp_engine_sel__size_1_v();
			perfmon_index++) {
		err = g->ops.gr.get_pm_ctx_buffer_offsets(g,
				perf_pmmfbp_engine_sel_r(perfmon_index),
				max_offsets,
				&buf_offset_lo,
				&buf_offset_addr,
				&num_offsets);
		if (err != 0U) {
			break;
		}
	}
	*num_fbp_perfmon = perfmon_index;

	for (perfmon_index = 0U; perfmon_index <
			perf_pmmgpc_engine_sel__size_1_v();
			perfmon_index++) {
		err = g->ops.gr.get_pm_ctx_buffer_offsets(g,
				perf_pmmgpc_engine_sel_r(perfmon_index),
				max_offsets,
				&buf_offset_lo,
				&buf_offset_addr,
				&num_offsets);
		if (err != 0U) {
			break;
		}
	}
	*num_gpc_perfmon = perfmon_index;
}

void ga10b_perf_init_hwpm_pmm_register(struct gk20a *g)
{
	/* Recheck g10ab can support more  than one chiplet */
	u32 num_chiplets    = 1U;
	u32 base_index      = 0U;
	u32 data            = 0U;
	u32 i               = 0U;

	g->ops.perf.set_pmm_register(g, perf_pmmsys_engine_sel_r(base_index),
				   U32_MAX, num_chiplets,
				   g->ops.perf.get_pmmsys_per_chiplet_offset(),
				   g->num_sys_perfmon);
	g->ops.perf.set_pmm_register(g, perf_pmmfbp_engine_sel_r(base_index),
				   U32_MAX, nvgpu_fbp_get_num_fbps(g->fbp),
				   g->ops.perf.get_pmmfbp_per_chiplet_offset(),
				   g->num_fbp_perfmon);
	g->ops.perf.set_pmm_register(g, perf_pmmgpc_engine_sel_r(base_index),
				   U32_MAX,
				   nvgpu_gr_config_get_gpc_count(nvgpu_gr_get_config_ptr(g)),
				   g->ops.perf.get_pmmgpc_per_chiplet_offset(),
				   g->num_gpc_perfmon);

	nvgpu_assert(perf_pmasys_channel_config_user__size_1_v() ==
				pmasys_channel_instance_max_size);

	data = nvgpu_readl(g, perf_pmasys_controlb_r());
	data = set_field(data,
		perf_pmasys_controlb_coalesce_timeout_cycles_m(),
		perf_pmasys_controlb_coalesce_timeout_cycles__prod_f());
	nvgpu_writel(g, perf_pmasys_controlb_r(), data);

	for (i = 0U; i < perf_pmasys_channel_config_user__size_1_v(); i++) {
		data = nvgpu_readl(g, perf_pmasys_channel_config_user_r(i));
		data = set_field(data,
			perf_pmasys_channel_config_user_coalesce_timeout_cycles_m(),
			perf_pmasys_channel_config_user_coalesce_timeout_cycles__prod_f());
		nvgpu_writel(g, perf_pmasys_channel_config_user_r(i), data);
	}

	if (g->ops.priv_ring.read_pri_fence != NULL) {
		/* Read back to ensure all writes are complete */
		g->ops.priv_ring.read_pri_fence(g);
	}
}

void ga10b_perf_disable_all_perfmons(struct gk20a *g)
{
	g->ops.perf.set_pmm_register(g, perf_pmmsys_control_r(0U), 0U, 1U,
		g->ops.perf.get_pmmsys_per_chiplet_offset(),
		g->num_sys_perfmon);

	g->ops.perf.set_pmm_register(g, perf_pmmfbp_fbps_control_r(0U), 0U, 1U,
		g->ops.perf.get_pmmfbp_per_chiplet_offset(),
		g->num_fbp_perfmon);

	g->ops.perf.set_pmm_register(g, perf_pmmgpc_gpcs_control_r(0U), 0U, 1U,
		g->ops.perf.get_pmmgpc_per_chiplet_offset(),
		g->num_gpc_perfmon);

	if (g->ops.priv_ring.read_pri_fence != NULL) {
		g->ops.priv_ring.read_pri_fence(g);
	}
}

int ga10b_perf_update_get_put(struct gk20a *g, u64 bytes_consumed,
		bool update_available_bytes, u64 *put_ptr,
		bool *overflowed)
{
	u32 val;

	nvgpu_assert(perf_pmasys_channel_mem_bump__size_1_v() ==
				pmasys_channel_instance_max_size);
	nvgpu_assert(perf_pmasys_channel_control_user__size_1_v() ==
				pmasys_channel_instance_max_size);
	nvgpu_assert(perf_pmasys_channel_mem_head__size_1_v() ==
				pmasys_channel_instance_max_size);


	if (bytes_consumed != 0U) {
		nvgpu_writel(g, perf_pmasys_channel_mem_bump_r(inst_zero), (u32)bytes_consumed);
	}

	if (update_available_bytes) {
		val = nvgpu_readl(g, perf_pmasys_channel_control_user_r(inst_zero));
		val = set_field(val, perf_pmasys_channel_control_user_update_bytes_m(),
				     perf_pmasys_channel_control_user_update_bytes_doit_f());
		nvgpu_writel(g, perf_pmasys_channel_control_user_r(inst_zero), val);
	}

	if (put_ptr) {
		*put_ptr = (u64)nvgpu_readl(g, perf_pmasys_channel_mem_head_r(inst_zero));
	}

	if (overflowed) {
		*overflowed = g->ops.perf.get_membuf_overflow_status(g);
	}

	return 0;
}

void ga10b_perf_pma_stream_enable(struct gk20a *g, bool enable)
{
	u32 reg_val;

	nvgpu_assert(perf_pmasys_channel_control_user__size_1_v() ==
				pmasys_channel_instance_max_size);

	reg_val = nvgpu_readl(g, perf_pmasys_channel_control_user_r(inst_zero));

	if (enable) {
		reg_val = set_field(reg_val,
				perf_pmasys_channel_control_user_stream_m(),
				perf_pmasys_channel_control_user_stream_enable_f());
	} else {
		reg_val = set_field(reg_val,
				perf_pmasys_channel_control_user_stream_m(),
				perf_pmasys_channel_control_user_stream_disable_f());
	}

	nvgpu_writel(g, perf_pmasys_channel_control_user_r(inst_zero), reg_val);
}

int ga10b_perf_wait_for_idle_pma(struct gk20a *g)
{
	struct nvgpu_timeout timeout;
	u32 status, rbufempty_status;
	u32 timeout_ms = 1;
	u32 reg_val;

	nvgpu_timeout_init_cpu_timer(g, &timeout, timeout_ms);

	do {
		reg_val = nvgpu_readl(g, perf_pmasys_enginestatus_r());

		status = perf_pmasys_enginestatus_status_v(reg_val);
		rbufempty_status = perf_pmasys_enginestatus_rbufempty_v(reg_val);

		if ((status == perf_pmasys_enginestatus_status_empty_v()) &&
		    (rbufempty_status == perf_pmasys_enginestatus_rbufempty_empty_v())) {
			return 0;
		}

		nvgpu_usleep_range(20, 40);
	} while (nvgpu_timeout_expired(&timeout) == 0);

	return -ETIMEDOUT;
}

void ga10b_perf_enable_hs_streaming(struct gk20a *g, bool enable)
{
	u32 num_gpc, num_fbp;
	u32 i;
	u32 val = 0;

	num_gpc = nvgpu_gr_config_get_gpc_count(nvgpu_gr_get_config_ptr(g));
	num_fbp = nvgpu_fbp_get_num_fbps(g->fbp);

	val = nvgpu_readl(g, perf_pmmsysrouter_global_cntrl_r());
	if (enable) {
		val = set_field(val, perf_pmmsysrouter_global_cntrl_hs_stream_enable_m(),
				perf_pmmsysrouter_global_cntrl_hs_stream_enable_true_f());
	} else {
		val = set_field(val, perf_pmmsysrouter_global_cntrl_hs_stream_enable_m(),
				perf_pmmsysrouter_global_cntrl_hs_stream_enable_false_f());
	}

	nvgpu_writel(g, perf_pmmsysrouter_global_cntrl_r(), val);

	for (i = 0U; i < num_gpc; ++i) {
		nvgpu_writel(g, perf_pmmgpcrouter_global_cntrl_r() + (i * PMM_ROUTER_OFFSET),
				val);
	}

	for (i = 0U; i < num_fbp; ++i) {
		nvgpu_writel(g, perf_pmmfbprouter_global_cntrl_r() + (i * PMM_ROUTER_OFFSET),
				val);
	}

	if (g->ops.priv_ring.read_pri_fence != NULL) {
		g->ops.priv_ring.read_pri_fence(g);
	}
}

void ga10b_perf_reset_hs_streaming_credits(struct gk20a *g)
{
	u32 num_gpc, num_fbp;
	u32 i;
	const u32 val = 0; // Set credits to 0.

	num_gpc = nvgpu_gr_config_get_gpc_count(nvgpu_gr_get_config_ptr(g));
	num_fbp = nvgpu_fbp_get_num_fbps(g->fbp);

	nvgpu_writel(g, perf_pmmsysrouter_hs_config_r(), val);
	for (i = 0U; i < num_gpc; ++i) {
		nvgpu_writel(g, perf_pmmgpcrouter_hs_config_r() + (i * PMM_ROUTER_OFFSET),
				val);
	}

	for (i = 0U; i < num_fbp; ++i) {
		nvgpu_writel(g, perf_pmmfbprouter_hs_config_r() + (i * PMM_ROUTER_OFFSET),
				val);
	}

	if (g->ops.priv_ring.read_pri_fence != NULL) {
		g->ops.priv_ring.read_pri_fence(g);
	}
}

void ga10b_perf_enable_pmasys_legacy_mode(struct gk20a *g, bool enable)
{
	u32 val = 0;

	val = nvgpu_readl(g, perf_pmasys_controlreg_r());
	if (enable) {
		val = set_field(val, perf_pmasys_controlreg_legacy_mode_m(),
				perf_pmasys_controlreg_legacy_mode_enable_f());
	} else {
		val = set_field(val, perf_pmasys_controlreg_legacy_mode_m(),
				perf_pmasys_controlreg_legacy_mode_disable_f());
	}

	nvgpu_writel(g, perf_pmasys_controlreg_r(), val);
}

void ga10b_perf_reset_hwpm_pma_registers(struct gk20a *g)
{
	u32 val = 0;
	u32 i = 0;


	for (i = 0U; i < perf_pmasys_trigger_config_user__size_1_v(); i++) {
		val = nvgpu_readl(g, perf_pmasys_trigger_config_user_r(i));

		val = set_field(val, perf_pmasys_trigger_config_user_pma_pulse_m(),
				perf_pmasys_trigger_config_user_pma_pulse_disable_f());
		val = set_field(val, perf_pmasys_trigger_config_user_pma_pulse_window_m(),
				perf_pmasys_trigger_config_user_pma_pulse_window_inside_f());
		val = set_field(val, perf_pmasys_trigger_config_user_pma_pulse_source_m(),
				perf_pmasys_trigger_config_user_pma_pulse_source_internal_f());
		val = set_field(val, perf_pmasys_trigger_config_user_pma_pulse_cntr_m(),
				perf_pmasys_trigger_config_user_pma_pulse_cntr_one_f());
		val = set_field(val, perf_pmasys_trigger_config_user_record_stream_m(),
				perf_pmasys_trigger_config_user_record_stream_disable_f());

		nvgpu_writel(g, perf_pmasys_trigger_config_user_r(i), val);
	}

	for (i = 0U; i < perf_pmasys_config1__size_1_v(); i++) {
		val = nvgpu_readl(g, perf_pmasys_config1_r(i));

		val = set_field(val, perf_pmasys_config1_bf_20_20_m(),
				perf_pmasys_config1_bf_20_20_disable_f());
		val = set_field(val, perf_pmasys_config1_bf_21_21_m(),
				perf_pmasys_config1_bf_21_21_enable_f());

		nvgpu_writel(g, perf_pmasys_config1_r(i), val);
	}

	for (i = 0U; i < perf_pmasys_config2__size_1_v(); i++) {
		val = nvgpu_readl(g, perf_pmasys_config2_r(i));

		val = set_field(val, perf_pmasys_config2_bf_0_0_m(),
			perf_pmasys_config2_bf_0_0_disable_f());

		nvgpu_writel(g, perf_pmasys_config2_r(i), val);
	}

	nvgpu_writel(g, perf_pmasys_pulse_timebaseset_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_pulse_timebasecnt_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_record_start_triggercnt_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_record_stop_triggercnt_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_record_total_triggercnt_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_trigger_global_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_router_config0_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_router_config1_r(), 0x0U);

	val = nvgpu_readl(g, perf_pmasys_controlb_r());
	val = set_field(val, perf_pmasys_controlb_coalesce_timeout_cycles_m(),
		perf_pmasys_controlb_coalesce_timeout_cycles_64_f());
	val = set_field(val, perf_pmasys_controlb_mbu_cya_smb_m(),
		perf_pmasys_controlb_mbu_cya_smb_disable_f());
	val = set_field(val, perf_pmasys_controlb_mbu_cya_ss_m(),
		perf_pmasys_controlb_mbu_cya_ss_disable_f());
	val = set_field(val, perf_pmasys_controlb_keep_latest_m(),
		perf_pmasys_controlb_keep_latest_disable_f());
	val = set_field(val, perf_pmasys_controlb_fault_nack_cya_m(),
		perf_pmasys_controlb_fault_nack_cya_disable_f());
	nvgpu_writel(g, perf_pmasys_controlb_r(), val);
}

void ga10b_perf_reset_hwpm_pma_trigger_registers(struct gk20a *g)
{
	nvgpu_writel(g, perf_pmasys_sys_trigger_start_mask_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_sys_trigger_start_maskb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_sys_trigger_stop_mask_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_sys_trigger_stop_maskb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_sys_trigger_config_tesla_mode_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_sys_trigger_config_tesla_modeb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_sys_trigger_config_mixed_mode_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_sys_trigger_config_mixed_modeb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_sys_trigger_start_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_sys_trigger_startb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_sys_trigger_status_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_sys_trigger_statusb_r(), 0x0U);

	nvgpu_writel(g, perf_pmasys_gpc_trigger_start_mask_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_gpc_trigger_start_maskb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_gpc_trigger_stop_mask_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_gpc_trigger_stop_maskb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_gpc_trigger_config_tesla_mode_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_gpc_trigger_config_tesla_modeb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_gpc_trigger_config_mixed_mode_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_gpc_trigger_config_mixed_modeb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_gpc_trigger_start_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_gpc_trigger_startb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_gpc_trigger_status_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_gpc_trigger_statusb_r(), 0x0U);

	nvgpu_writel(g, perf_pmasys_fbp_trigger_start_mask_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_fbp_trigger_start_maskb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_fbp_trigger_stop_mask_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_fbp_trigger_stop_maskb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_fbp_trigger_config_tesla_mode_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_fbp_trigger_config_tesla_modeb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_fbp_trigger_config_mixed_mode_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_fbp_trigger_config_mixed_modeb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_fbp_trigger_start_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_fbp_trigger_startb_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_fbp_trigger_status_r(), 0x0U);
	nvgpu_writel(g, perf_pmasys_fbp_trigger_statusb_r(), 0x0U);
}

void ga10b_perf_reset_pmasys_channel_registers(struct gk20a *g)
{
	u32 i = 0U;
	u32 val = 0U;

	for (i = 0U; i < perf_pmasys_channel_config_user__size_1_v(); i++) {
		val = nvgpu_readl(g, perf_pmasys_channel_config_user_r(i));
		val = set_field(val, perf_pmasys_channel_config_user_keep_latest_m(),
			perf_pmasys_channel_config_user_keep_latest_disable_f());
		val = set_field(val, perf_pmasys_channel_config_user_coalesce_timeout_cycles_m(),
			perf_pmasys_channel_config_user_coalesce_timeout_cycles_64_f());
		nvgpu_writel(g, perf_pmasys_channel_config_user_r(i), val);
	}

	for (i = 0U; i < perf_pmasys_config3__size_1_v(); i++) {
		val = nvgpu_readl(g, perf_pmasys_config3_r(i));
		val = set_field(val, perf_pmasys_config3_bf_1_1_m(),
			perf_pmasys_config3_bf_1_1_disable_f());
		val = set_field(val, perf_pmasys_config3_bf_2_2_m(),
			perf_pmasys_config3_bf_2_2_disable_f());
		val = set_field(val, perf_pmasys_config3_bf_3_3_m(),
			perf_pmasys_config3_bf_3_3_disable_f());
		nvgpu_writel(g, perf_pmasys_config3_r(i), val);
	}

	for (i = 0U; i < perf_pmasys_channel_control__size_1_v(); i++) {
		val = nvgpu_readl(g, perf_pmasys_channel_control_r(i));
		val = set_field(val, perf_pmasys_channel_control_stream_m(),
			perf_pmasys_channel_control_stream_disable_f());
		val = set_field(val, perf_pmasys_channel_control_pmactxsw_mode_m(),
			perf_pmasys_channel_control_pmactxsw_mode_enable_f());
		val = set_field(val, perf_pmasys_channel_control_pma_record_stream_m(),
			perf_pmasys_channel_control_pma_record_stream_disable_f());
		val = set_field(val, perf_pmasys_channel_control_fe2all_ctxsw_freeze_enable_m(),
			perf_pmasys_channel_control_fe2all_ctxsw_freeze_enable_true_f());
		val = set_field(val, perf_pmasys_channel_control_pma_ctxsw_freeze_m(),
			perf_pmasys_channel_control_pma_ctxsw_freeze_false_f());
		nvgpu_writel(g, perf_pmasys_channel_control_r(i), val);
	}

	for (i = 0U; i < perf_pmasys_channel_control_user__size_1_v(); i++) {
		val = nvgpu_readl(g, perf_pmasys_channel_control_user_r(i));
		val = set_field(val, perf_pmasys_channel_control_user_stream_m(),
			perf_pmasys_channel_control_user_stream_disable_f());
		val = set_field(val, perf_pmasys_channel_control_user_membuf_clear_status_m(),
			perf_pmasys_channel_control_user_membuf_clear_status_init_f());
		val = set_field(val, perf_pmasys_channel_control_user_flush_coalesce_fifo_m(),
			perf_pmasys_channel_control_user_flush_coalesce_fifo_init_f());
		val = set_field(val, perf_pmasys_channel_control_user_send_bind_m(),
			perf_pmasys_channel_control_user_send_bind_init_f());
		val = set_field(val, perf_pmasys_channel_control_user_reset_data_fifo_m(),
			perf_pmasys_channel_control_user_reset_data_fifo_init_f());
		val = set_field(val, perf_pmasys_channel_control_user_update_bytes_m(),
			perf_pmasys_channel_control_user_update_bytes_init_f());
		nvgpu_writel(g, perf_pmasys_channel_control_user_r(i), val);
	}
}
