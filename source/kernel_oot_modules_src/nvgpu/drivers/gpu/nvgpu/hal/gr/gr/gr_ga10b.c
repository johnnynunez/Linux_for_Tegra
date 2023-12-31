/*
 * GA10b GPU GR
 *
 * Copyright (c) 2020-2022, NVIDIA CORPORATION.  All rights reserved.
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

#include <nvgpu/dma.h>
#include <nvgpu/log.h>
#include <nvgpu/bug.h>
#include <nvgpu/debug.h>
#include <nvgpu/enabled.h>
#include <nvgpu/fuse.h>
#include <nvgpu/debugger.h>
#include <nvgpu/error_notifier.h>
#include <nvgpu/io.h>
#include <nvgpu/utils.h>
#include <nvgpu/bitops.h>
#include <nvgpu/gk20a.h>
#include <nvgpu/regops.h>
#include <nvgpu/gr/ctx.h>
#include <nvgpu/gr/config.h>
#include <nvgpu/gr/gr.h>
#include <nvgpu/gr/gr_instances.h>
#include <nvgpu/gr/warpstate.h>
#include <nvgpu/channel.h>
#include <nvgpu/engines.h>
#include <nvgpu/engine_status.h>
#include <nvgpu/fbp.h>
#include <nvgpu/nvgpu_err.h>
#include <nvgpu/netlist.h>
#include <nvgpu/gr/obj_ctx.h>

#include "gr_ga10b.h"
#include "hal/gr/gr/gr_gk20a.h"
#include "hal/gr/gr/gr_gv11b.h"
#include "hal/gr/gr/gr_pri_gk20a.h"
#include "hal/gr/gr/gr_pri_ga10b.h"
#include "hal/gr/ctxsw_prog/ctxsw_prog_ga10b.h"
#include "common/gr/gr_priv.h"

#include <nvgpu/hw/ga10b/hw_gr_ga10b.h>
#include <nvgpu/hw/ga10b/hw_proj_ga10b.h>
#include <nvgpu/hw/ga10b/hw_ctxsw_prog_ga10b.h>

#define ILLEGAL_ID	~U32(0U)

static void gr_ga10b_dump_gr_per_sm_regs(struct gk20a *g,
			struct nvgpu_debug_context *o,
			u32 gpc, u32 tpc, u32 sm, u32 offset)
{
	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPC%d_TPC%d_SM%d_HWW_WARP_ESR: 0x%x\n",
		gpc, tpc, sm, nvgpu_readl(g,
		nvgpu_safe_add_u32(gr_gpc0_tpc0_sm0_hww_warp_esr_r(),
				   offset)));

	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPC%d_TPC%d_SM%d_HWW_WARP_ESR_REPORT_MASK: 0x%x\n",
		gpc, tpc, sm, nvgpu_readl(g,
		nvgpu_safe_add_u32(gr_gpc0_tpc0_sm0_hww_warp_esr_report_mask_r(),
				   offset)));

	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPC%d_TPC%d_SM%d_HWW_GLOBAL_ESR: 0x%x\n",
		gpc, tpc, sm, nvgpu_readl(g,
		nvgpu_safe_add_u32(gr_gpc0_tpc0_sm0_hww_global_esr_r(),
				   offset)));

	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPC%d_TPC%d_SM%d_HWW_GLOBAL_ESR_REPORT_MASK: 0x%x\n",
		gpc, tpc, sm, nvgpu_readl(g,
		nvgpu_safe_add_u32(gr_gpc0_tpc0_sm0_hww_global_esr_report_mask_r(),
				   offset)));

	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPC%d_TPC%d_SM%d_DBGR_CONTROL0: 0x%x\n",
		gpc, tpc, sm, nvgpu_readl(g,
		nvgpu_safe_add_u32(gr_gpc0_tpc0_sm0_dbgr_control0_r(),
				   offset)));

	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPC%d_TPC%d_SM%d_DBGR_STATUS0: 0x%x\n",
		gpc, tpc, sm, nvgpu_readl(g,
		nvgpu_safe_add_u32(gr_gpc0_tpc0_sm0_dbgr_status0_r(),
				   offset)));
}

static void gr_ga10b_dump_gr_sm_regs(struct gk20a *g,
			   struct nvgpu_debug_context *o)
{
	u32 gpc, tpc, sm, sm_per_tpc;
	u32 gpc_offset, tpc_offset, offset;
	struct nvgpu_gr *gr = nvgpu_gr_get_cur_instance_ptr(g);

	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPCS_TPCS_SMS_HWW_GLOBAL_ESR_REPORT_MASK: 0x%x\n",
		nvgpu_readl(g,
		gr_gpcs_tpcs_sms_hww_global_esr_report_mask_r()));
	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPCS_TPCS_SMS_HWW_WARP_ESR_REPORT_MASK: 0x%x\n",
		nvgpu_readl(g, gr_gpcs_tpcs_sms_hww_warp_esr_report_mask_r()));
	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPCS_TPCS_SMS_HWW_GLOBAL_ESR: 0x%x\n",
		nvgpu_readl(g, gr_gpcs_tpcs_sms_hww_global_esr_r()));
	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPCS_TPCS_SMS_DBGR_CONTROL0: 0x%x\n",
		nvgpu_readl(g, gr_gpcs_tpcs_sms_dbgr_control0_r()));
	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPCS_TPCS_SMS_DBGR_STATUS0: 0x%x\n",
		nvgpu_readl(g, gr_gpcs_tpcs_sms_dbgr_status0_r()));
	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPCS_TPCS_SMS_DBGR_BPT_PAUSE_MASK_0: 0x%x\n",
		nvgpu_readl(g, gr_gpcs_tpcs_sms_dbgr_bpt_pause_mask_0_r()));
	gk20a_debug_output(o,
		"NV_PGRAPH_PRI_GPCS_TPCS_SMS_DBGR_BPT_PAUSE_MASK_1: 0x%x\n",
		nvgpu_readl(g, gr_gpcs_tpcs_sms_dbgr_bpt_pause_mask_1_r()));

	sm_per_tpc = nvgpu_get_litter_value(g, GPU_LIT_NUM_SM_PER_TPC);
	for (gpc = 0U;
	     gpc < nvgpu_gr_config_get_gpc_count(gr->config); gpc++) {
		gpc_offset = nvgpu_gr_gpc_offset(g, gpc);

		for (tpc = 0U;
		     tpc < nvgpu_gr_config_get_gpc_tpc_count(gr->config, gpc);
		     tpc++) {
			tpc_offset = nvgpu_gr_tpc_offset(g, tpc);

			for (sm = 0U; sm < sm_per_tpc; sm++) {
				offset = nvgpu_safe_add_u32(
						nvgpu_safe_add_u32(gpc_offset,
								   tpc_offset),
						nvgpu_gr_sm_offset(g, sm));

				gr_ga10b_dump_gr_per_sm_regs(g, o,
					gpc, tpc, sm, offset);
			}
		}
	}
}

static void gr_ga10b_dump_tpc_activity_regs(struct gk20a *g,
					    struct nvgpu_debug_context *o)
{
	struct nvgpu_gr *gr = nvgpu_gr_get_cur_instance_ptr(g);
	u32 gpc_index = 0U;
	u32 tpc_count = 0U, tpc_stride = 0U;
	u32 reg_index = 0U, offset = 0U;
	u32 i = 0U;

	if (nvgpu_gr_config_get_base_count_gpc_tpc(gr->config) == NULL) {
		return;
	}

	tpc_count = nvgpu_gr_config_get_gpc_tpc_count(gr->config, gpc_index);
	tpc_stride = nvgpu_get_litter_value(g, GPU_LIT_TPC_IN_GPC_STRIDE);

	for (i = 0U; i < tpc_count; i++) {
		offset = nvgpu_safe_mult_u32(tpc_stride, i);
		reg_index = nvgpu_safe_add_u32(offset,
				gr_pri_gpc0_tpc0_tpccs_tpc_activity_0_r());

		gk20a_debug_output(o,
			"NV_PGRAPH_PRI_GPC0_TPC%d_TPCCS_TPC_ACTIVITY0: 0x%x\n",
			i, nvgpu_readl(g, reg_index));
	}
}

int gr_ga10b_dump_gr_status_regs(struct gk20a *g,
				 struct nvgpu_debug_context *o)
{
	u32 gr_engine_id;
	struct nvgpu_engine_status_info engine_status;

	gr_engine_id = nvgpu_engine_get_gr_id(g);

	gk20a_debug_output(o, "NV_PGRAPH_STATUS: 0x%x\n",
		nvgpu_readl(g, gr_status_r()));
	gk20a_debug_output(o, "NV_PGRAPH_STATUS1: 0x%x\n",
		nvgpu_readl(g, gr_status_1_r()));
	gk20a_debug_output(o, "NV_PGRAPH_ENGINE_STATUS: 0x%x\n",
		nvgpu_readl(g, gr_engine_status_r()));
	gk20a_debug_output(o, "NV_PGRAPH_GRFIFO_STATUS : 0x%x\n",
		nvgpu_readl(g, gr_gpfifo_status_r()));
	gk20a_debug_output(o, "NV_PGRAPH_GRFIFO_CONTROL : 0x%x\n",
		nvgpu_readl(g, gr_gpfifo_ctl_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_FECS_HOST_INT_STATUS : 0x%x\n",
		nvgpu_readl(g, gr_fecs_host_int_status_r()));
	gk20a_debug_output(o, "NV_PGRAPH_EXCEPTION  : 0x%x\n",
		nvgpu_readl(g, gr_exception_r()));
	gk20a_debug_output(o, "NV_PGRAPH_FECS_INTR  : 0x%x\n",
		nvgpu_readl(g, gr_fecs_intr_r()));
	g->ops.engine_status.read_engine_status_info(g, gr_engine_id,
		&engine_status);
	gk20a_debug_output(o, "NV_PFIFO_ENGINE_STATUS(GR) : 0x%x\n",
		engine_status.reg_data);
	gk20a_debug_output(o, "NV_PGRAPH_ACTIVITY0: 0x%x\n",
		nvgpu_readl(g, gr_activity_0_r()));
	gk20a_debug_output(o, "NV_PGRAPH_ACTIVITY1: 0x%x\n",
		nvgpu_readl(g, gr_activity_1_r()));
	gk20a_debug_output(o, "NV_PGRAPH_ACTIVITY4: 0x%x\n",
		nvgpu_readl(g, gr_activity_4_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_SKED_ACTIVITY: 0x%x\n",
		nvgpu_readl(g, gr_pri_sked_activity_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_GPCCS_GPC_ACTIVITY0: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpc0_gpccs_gpc_activity0_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_GPCCS_GPC_ACTIVITY1: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpc0_gpccs_gpc_activity1_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_GPCCS_GPC_ACTIVITY2: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpc0_gpccs_gpc_activity2_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_GPCCS_GPC_ACTIVITY3: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpc0_gpccs_gpc_activity3_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_GPCCS_GPC_ACTIVITY4: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpc0_gpccs_gpc_activity4_r()));

	gr_ga10b_dump_tpc_activity_regs(g,o);

	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_GPCCS_GPC_ACTIVITY0: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpcs_gpccs_gpc_activity_0_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_GPCCS_GPC_ACTIVITY1: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpcs_gpccs_gpc_activity_1_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_GPCCS_GPC_ACTIVITY2: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpcs_gpccs_gpc_activity_2_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_GPCCS_GPC_ACTIVITY3: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpcs_gpccs_gpc_activity_3_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_GPCCS_GPC_ACTIVITY4: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpcs_gpccs_gpc_activity_4_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_TPCS_TPCCS_TPC_ACTIVITY0: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpcs_tpcs_tpccs_tpc_activity_0_r()));
	if (!nvgpu_is_enabled(g, NVGPU_SUPPORT_MIG)) {
		gk20a_debug_output(o, "NV_PGRAPH_PRI_DS_MPIPE_STATUS: 0x%x\n",
			nvgpu_readl(g, gr_pri_ds_mpipe_status_r()));
	}
	gk20a_debug_output(o, "NV_PGRAPH_PRI_FE_GO_IDLE_TIMEOUT : 0x%x\n",
		nvgpu_readl(g, gr_fe_go_idle_timeout_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_FE_GO_IDLE_INFO : 0x%x\n",
		nvgpu_readl(g, gr_pri_fe_go_idle_info_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_TPC0_TEX_M_TEX_SUBUNITS_STATUS: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpc0_tpc0_tex_m_tex_subunits_status_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_CWD_FS: 0x%x\n",
		nvgpu_readl(g, gr_cwd_fs_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_FE_TPC_FS(0): 0x%x\n",
		nvgpu_readl(g, gr_fe_tpc_fs_r(0)));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_CWD_GPC_TPC_ID: 0x%x\n",
		nvgpu_readl(g, gr_cwd_gpc_tpc_id_r(0)));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_CWD_SM_ID(0): 0x%x\n",
		nvgpu_readl(g, gr_cwd_sm_id_r(0)));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_FECS_CTXSW_STATUS_FE_0: 0x%x\n",
		g->ops.gr.falcon.read_fecs_ctxsw_status0(g));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_FECS_CTXSW_STATUS_1: 0x%x\n",
		g->ops.gr.falcon.read_fecs_ctxsw_status1(g));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_GPCCS_CTXSW_STATUS_GPC_0: 0x%x\n",
		nvgpu_readl(g, gr_gpc0_gpccs_ctxsw_status_gpc_0_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_GPCCS_CTXSW_STATUS_1: 0x%x\n",
		nvgpu_readl(g, gr_gpc0_gpccs_ctxsw_status_1_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_FECS_CTXSW_IDLESTATE : 0x%x\n",
		nvgpu_readl(g, gr_fecs_ctxsw_idlestate_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_GPCCS_CTXSW_IDLESTATE : 0x%x\n",
		nvgpu_readl(g, gr_gpc0_gpccs_ctxsw_idlestate_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_FECS_CURRENT_CTX : 0x%x\n",
		g->ops.gr.falcon.get_current_ctx(g));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_FECS_NEW_CTX : 0x%x\n",
		nvgpu_readl(g, gr_fecs_new_ctx_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_FECS_HOST_INT_ENABLE : 0x%x\n",
		nvgpu_readl(g, gr_fecs_host_int_enable_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_FECS_HOST_INT_STATUS : 0x%x\n",
		nvgpu_readl(g, gr_fecs_host_int_status_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_ROP0_CROP_STATUS1 : 0x%x\n",
		nvgpu_readl(g, gr_pri_gpcs_rop0_crop_status1_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_ROPS_CROP_STATUS1 : 0x%x\n",
		nvgpu_readl(g, gr_pri_gpcs_rops_crop_status1_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_ROP0_ZROP_STATUS : 0x%x\n",
		nvgpu_readl(g, gr_pri_gpcs_rop0_zrop_status_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_ROP0_ZROP_STATUS2 : 0x%x\n",
		nvgpu_readl(g, gr_pri_gpcs_rop0_zrop_status2_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_ROP1_ZROP_STATUS: 0x%x\n",
		nvgpu_readl(g, nvgpu_safe_add_u32(
			gr_pri_gpcs_rop0_zrop_status_r(),
			nvgpu_get_litter_value(g, GPU_LIT_ROP_STRIDE))));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_ROP1_ZROP_STATUS2: 0x%x\n",
		nvgpu_readl(g, nvgpu_safe_add_u32(
			gr_pri_gpcs_rop0_zrop_status2_r(),
			nvgpu_get_litter_value(g, GPU_LIT_ROP_STRIDE))));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_ROPS_ZROP_STATUS : 0x%x\n",
		nvgpu_readl(g, gr_pri_gpcs_rops_zrop_status_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPCS_ROPS_ZROP_STATUS2 : 0x%x\n",
		nvgpu_readl(g, gr_pri_gpcs_rops_zrop_status2_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_GPCCS_GPC_EXCEPTION: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpc0_gpccs_gpc_exception_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_GPCCS_GPC_EXCEPTION_EN: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpc0_gpccs_gpc_exception_en_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_TPC0_TPCCS_TPC_EXCEPTION: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpc0_tpc0_tpccs_tpc_exception_r()));
	gk20a_debug_output(o, "NV_PGRAPH_PRI_GPC0_TPC0_TPCCS_TPC_EXCEPTION_EN: 0x%x\n",
		nvgpu_readl(g, gr_pri_gpc0_tpc0_tpccs_tpc_exception_en_r()));

	gr_ga10b_dump_gr_sm_regs(g, o);

	return 0;
}

void gr_ga10b_set_circular_buffer_size(struct gk20a *g, u32 data)
{
	struct nvgpu_gr *gr = nvgpu_gr_get_cur_instance_ptr(g);
	u32 gpc_index, ppc_index, stride, val;
	u32 cb_size_steady = data * 4U, cb_size;
	u32 attrib_cb_size = g->ops.gr.init.get_attrib_cb_size(g,
		nvgpu_gr_config_get_tpc_count(gr->config));

	nvgpu_log_fn(g, " ");

	if (cb_size_steady > attrib_cb_size) {
		cb_size_steady = attrib_cb_size;
	}
	if (nvgpu_readl(g, gr_gpc0_ppc0_cbm_beta_cb_size_r()) !=
		nvgpu_readl(g,
			gr_gpc0_ppc0_cbm_beta_steady_state_cb_size_r())) {
		cb_size = cb_size_steady +
			(gr_gpc0_ppc0_cbm_beta_cb_size_v_gfxp_v() -
			 gr_gpc0_ppc0_cbm_beta_cb_size_v_default_v());
	} else {
		cb_size = cb_size_steady;
	}

	nvgpu_writel(g, gr_ds_tga_constraintlogic_beta_r(),
		(nvgpu_readl(g, gr_ds_tga_constraintlogic_beta_r()) &
		 ~gr_ds_tga_constraintlogic_beta_cbsize_f(~U32(0U))) |
		 gr_ds_tga_constraintlogic_beta_cbsize_f(cb_size_steady));

	for (gpc_index = 0;
	     gpc_index < nvgpu_gr_config_get_gpc_count(gr->config);
	     gpc_index++) {
		stride = proj_gpc_stride_v() * gpc_index;

		for (ppc_index = 0;
		     ppc_index < nvgpu_gr_config_get_gpc_ppc_count(gr->config, gpc_index);
		     ppc_index++) {

			val = nvgpu_readl(g, gr_gpc0_ppc0_cbm_beta_cb_size_r() +
				stride +
				proj_ppc_in_gpc_stride_v() * ppc_index);

			val = set_field(val,
				gr_gpc0_ppc0_cbm_beta_cb_size_v_m(),
				gr_gpc0_ppc0_cbm_beta_cb_size_v_f(cb_size *
					nvgpu_gr_config_get_pes_tpc_count(gr->config,
						gpc_index, ppc_index)));

			nvgpu_writel(g, gr_gpc0_ppc0_cbm_beta_cb_size_r() +
				stride +
				proj_ppc_in_gpc_stride_v() * ppc_index, val);

			nvgpu_writel(g, proj_ppc_in_gpc_stride_v() * ppc_index +
				gr_gpc0_ppc0_cbm_beta_steady_state_cb_size_r() +
				stride,
				gr_gpc0_ppc0_cbm_beta_steady_state_cb_size_v_f(
					cb_size_steady));

			val = nvgpu_readl(g, gr_gpcs_swdx_tc_beta_cb_size_r(
						ppc_index + gpc_index));

			val = set_field(val,
				gr_gpcs_swdx_tc_beta_cb_size_v_m(),
				gr_gpcs_swdx_tc_beta_cb_size_v_f(
					cb_size_steady *
					nvgpu_gr_config_get_gpc_ppc_count(gr->config, gpc_index)));

			nvgpu_writel(g, gr_gpcs_swdx_tc_beta_cb_size_r(
						ppc_index + gpc_index), val);
		}
	}
}

void ga10b_gr_set_gpcs_rops_crop_debug4(struct gk20a *g, u32 data)
{
	u32 val;

	nvgpu_log_fn(g, " ");

	val = nvgpu_readl(g, gr_pri_gpcs_rops_crop_debug4_r());
	if ((data & gr_pri_gpcs_rops_crop_debug4_clamp_fp_blend_s()) ==
		gr_pri_gpcs_rops_crop_debug4_clamp_fp_blend_to_maxval_v()) {
		val = set_field(val,
			gr_pri_gpcs_rops_crop_debug4_clamp_fp_blend_m(),
			gr_pri_gpcs_rops_crop_debug4_clamp_fp_blend_to_maxval_f());
	} else if ((data & gr_pri_gpcs_rops_crop_debug4_clamp_fp_blend_s()) ==
		gr_pri_gpcs_rops_crop_debug4_clamp_fp_blend_to_inf_v()) {
		val = set_field(val,
			gr_pri_gpcs_rops_crop_debug4_clamp_fp_blend_m(),
			gr_pri_gpcs_rops_crop_debug4_clamp_fp_blend_to_inf_f());
	} else {
		nvgpu_warn(g,
			"wrong data sent for crop_debug4: %x08x", data);
		return;
	}
	nvgpu_writel(g, gr_pri_gpcs_rops_crop_debug4_r(), val);
}

#ifdef CONFIG_NVGPU_DEBUGGER
bool ga10b_gr_check_warp_esr_error(struct gk20a *g, u32 warp_esr_error)
{
	u32 index = 0U;
	bool esr_err = false;

	struct warp_esr_error_table_s {
		u32 error_value;
		const char *error_name;
	};

	struct warp_esr_error_table_s warp_esr_error_table[] = {
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_api_stack_error_f(),
				"API STACK ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_misaligned_pc_f(),
				"MISALIGNED PC ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_pc_overflow_f(),
				"PC OVERFLOW ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_misaligned_reg_f(),
				"MISALIGNED REG ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_illegal_instr_encoding_f(),
				"ILLEGAL INSTRUCTION ENCODING ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_illegal_instr_param_f(),
				"ILLEGAL INSTRUCTION PARAM ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_oor_reg_f(),
				"OOR REG ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_oor_addr_f(),
				"OOR ADDR ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_misaligned_addr_f(),
				"MISALIGNED ADDR ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_invalid_addr_space_f(),
				"INVALID ADDR SPACE ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_invalid_const_addr_ldc_f(),
				"INVALID ADDR LDC ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_mmu_fault_f(),
				"MMU FAULT ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_tex_format_f(),
				"TEX FORMAT ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_tex_layout_f(),
				"TEX LAYOUT ERROR"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_mmu_nack_f(),
				"MMU NACK"},
		{ gr_gpc0_tpc0_sm0_hww_warp_esr_error_arrive_f(),
				"ARRIVE ERROR"},
	};

	for (index = 0; index < ARRAY_SIZE(warp_esr_error_table); index++) {
		if (warp_esr_error_table[index].error_value == warp_esr_error) {
			esr_err = true;
			nvgpu_log(g, gpu_dbg_fn | gpu_dbg_gpu_dbg,
				"WARP_ESR %s(0x%x)",
				warp_esr_error_table[index].error_name,
				esr_err);
			break;
		}
	}

	return esr_err;
}


/*
 * The context switched registers are saved as part of the context switch
 * image.
 *
 * The regops interface writes/reads these location within the saved context
 * switch image when the context is not resident.
 */

/*
 * This function will decode a priv address and return the partition
 * type and numbers
 */
int gr_ga10b_decode_priv_addr(struct gk20a *g, u32 addr,
	enum ctxsw_addr_type *addr_type,
	u32 *gpc_num, u32 *tpc_num, u32 *ppc_num, u32 *be_num,
	u32 *broadcast_flags)
{
	u32 gpc_addr;

	/*
	 * Special handling for registers under: ctx_reg_LTS_bc
	 *
	 * Unlike the other ltc registers which are stored as part of
	 * pm_ctxsw buffer these are stored in fecs ctxsw image priv
	 * segment regionid: NETLIST_REGIONID_CTXREG_LTS.
	 */
	if (g->ops.ltc.pri_is_ltc_addr(g, addr) &&
			g->ops.ltc.pri_is_lts_tstg_addr(g, addr)) {
		*addr_type = CTXSW_ADDR_TYPE_LTS_MAIN;
		if (g->ops.ltc.is_ltcs_ltss_addr(g, addr)) {
			*broadcast_flags |= PRI_BROADCAST_FLAGS_LTCS;
		} else if (g->ops.ltc.is_ltcn_ltss_addr(g, addr)) {
			*broadcast_flags |= PRI_BROADCAST_FLAGS_LTSS;
		}
		return 0;
	} else if (nvgpu_is_enabled(g, NVGPU_SUPPORT_ROP_IN_GPC) &&
			pri_is_gpc_addr(g, addr)) {
		gpc_addr = pri_gpccs_addr_mask(g, addr);
		if (pri_is_rop_in_gpc_addr(g, gpc_addr)) {
			if (pri_is_rop_in_gpc_addr_shared(g, gpc_addr)) {
				*broadcast_flags |=
					PRI_BROADCAST_FLAGS_ROP;
			}
			*addr_type = CTXSW_ADDR_TYPE_ROP;
			return 0;
		}
	}

	return gr_gv11b_decode_priv_addr(g, addr, addr_type, gpc_num,
			tpc_num, ppc_num, be_num, broadcast_flags);
}

int gr_ga10b_create_priv_addr_table(struct gk20a *g,
					   u32 addr,
					   u32 *priv_addr_table,
					   u32 *num_registers)
{
	enum ctxsw_addr_type addr_type;
	u32 gpc_num = 0U, tpc_num = 0U, ppc_num = 0U, be_num = 0U;
	u32 broadcast_flags = 0U;
	u32 t;
	int err;

	t = 0U;
	*num_registers = 0U;

	nvgpu_log(g, gpu_dbg_gpu_dbg, "addr=0x%x", addr);

	err = g->ops.gr.decode_priv_addr(g, addr, &addr_type,
					&gpc_num, &tpc_num, &ppc_num, &be_num,
					&broadcast_flags);
	nvgpu_log(g, gpu_dbg_gpu_dbg, "addr_type = %d", addr_type);
	if (err != 0) {
		return err;
	}

	/*
	 * The LIST_ctx_reg_LTS_bc contains broadcast registers; So, convert
	 * LTS unicast addresses of the form LTCnLTSn, LTCSLTSn, LTCnLTSS to
	 * LTCSLTSS.
	 */
	if (addr_type == CTXSW_ADDR_TYPE_LTS_MAIN) {
		if (broadcast_flags & PRI_BROADCAST_FLAGS_LTCS) {
			priv_addr_table[t++] = addr;
		} else {
			priv_addr_table[t++] =
				g->ops.ltc.pri_shared_addr(g, addr);
		}
		*num_registers = t;
		return 0;
	}

	/*
	 * At present the LIST_pm_ctx_reg_ROP contains only broadcast addresses.
	 * Hence, ROP unicast addresses are not ctxsw'ed, only broadcast
	 * addresses are ctxsw'ed. Therefore, convert all ROP unicast addresses
	 * to broadcast.
	 */
	if (addr_type == CTXSW_ADDR_TYPE_ROP) {
		if (broadcast_flags & PRI_BROADCAST_FLAGS_ROP) {
			priv_addr_table[t++] = addr;
		} else {
			priv_addr_table[t++] =
				pri_rop_in_gpc_shared_addr(g, addr);
		}
		*num_registers = t;
		return 0;
	}

	return gr_gv11b_create_priv_addr_table(g, addr, priv_addr_table, num_registers);
}

/*
 * The sys, tpc, etpc, ppc and gpc ctxsw_reg bundles are divided into compute
 * and gfx list. lts being the exception here, which still uses a single list.
 * So, for any given pri address first search in the compute list
 * followed by graphics list. On finding a match it returns the following:
 * - FOUND_IN_CTXSWBUF_PRIV_REGLIST: legacy priv reglist.
 * - FOUND_IN_CTXSWBUF_PRIV_COMPUTE_REGLIST: new compute priv reglist.
 * - FOUND_IN_CTXSWBUF_PRIV_GFX_REGLIST: new graphics priv reglist.
 */
int gr_ga10b_process_context_buffer_priv_segment(struct gk20a *g,
					     enum ctxsw_addr_type addr_type,
					     u32 pri_addr,
					     u32 gpc_num, u32 num_tpcs,
					     u32 num_ppcs, u32 ppc_mask,
					     u32 *priv_offset)
{
	u32 i;
	u32 address, base_address;
	u32 sys_offset, gpc_offset, tpc_offset, ppc_offset;
	u32 ppc_num, tpc_num, tpc_addr, gpc_addr, ppc_addr;
	struct netlist_aiv_list *list;
	struct netlist_aiv *reg;
	u32 gpc_base = nvgpu_get_litter_value(g, GPU_LIT_GPC_BASE);
	u32 gpc_stride = nvgpu_get_litter_value(g, GPU_LIT_GPC_STRIDE);
	u32 ppc_in_gpc_base = nvgpu_get_litter_value(g, GPU_LIT_PPC_IN_GPC_BASE);
	u32 ppc_in_gpc_stride = nvgpu_get_litter_value(g, GPU_LIT_PPC_IN_GPC_STRIDE);
	u32 tpc_in_gpc_base = nvgpu_get_litter_value(g, GPU_LIT_TPC_IN_GPC_BASE);
	u32 tpc_in_gpc_stride = nvgpu_get_litter_value(g, GPU_LIT_TPC_IN_GPC_STRIDE);
	struct nvgpu_gr *gr;
	u32 *context_buffer;
	u32 tpc_segment_pri_layout;
	bool is_tpc_layout_interleaved = false;

	(void)ppc_mask;

	nvgpu_log(g, gpu_dbg_fn | gpu_dbg_gpu_dbg, "pri_addr=0x%x", pri_addr);

	if (!g->netlist_valid) {
		return -EINVAL;
	}

	gr = nvgpu_gr_get_cur_instance_ptr(g);
	context_buffer = nvgpu_gr_obj_ctx_get_local_golden_image_ptr(
			gr->golden_image);
	tpc_segment_pri_layout = g->ops.gr.ctxsw_prog.get_tpc_segment_pri_layout(g, context_buffer);
	nvgpu_assert(tpc_segment_pri_layout != ctxsw_prog_main_tpc_segment_pri_layout_v_invalid_v());
	is_tpc_layout_interleaved = (tpc_segment_pri_layout ==
			ctxsw_prog_main_tpc_segment_pri_layout_v_interleaved_v());

	/* Process the SYS/BE segment. */
	if ((addr_type == CTXSW_ADDR_TYPE_SYS) ||
	    (addr_type == CTXSW_ADDR_TYPE_ROP)) {
		list = nvgpu_netlist_get_sys_compute_ctxsw_regs(g);
		for (i = 0; i < list->count; i++) {
			reg = &list->l[i];
			address    = reg->addr;
			sys_offset = reg->index;

			if (pri_addr == address) {
				*priv_offset = sys_offset;
				return FOUND_IN_CTXSWBUF_PRIV_COMPUTE_REGLIST;
			}
		}
#ifdef CONFIG_NVGPU_GRAPHICS
		list = nvgpu_netlist_get_sys_gfx_ctxsw_regs(g);
		for (i = 0; i < list->count; i++) {
			reg = &list->l[i];
			address    = reg->addr;
			sys_offset = reg->index;

			if (pri_addr == address) {
				*priv_offset = sys_offset;
				return FOUND_IN_CTXSWBUF_PRIV_GFX_REGLIST;
			}
		}
#endif
	}

	/*
	 * Process the LTS segment.
	 */
	if (addr_type == CTXSW_ADDR_TYPE_LTS_MAIN) {
		list = nvgpu_netlist_get_lts_ctxsw_regs(g);
		for (i = 0; i < list->count; i++) {
			reg = &list->l[i];
			address = reg->addr;
			sys_offset = reg->index;

			if (pri_addr == address) {
				*priv_offset = sys_offset;
				return FOUND_IN_CTXSWBUF_PRIV_REGLIST;
			}
		}
	}

	/* Process the TPC segment. */
	if (addr_type == CTXSW_ADDR_TYPE_TPC) {
		for (tpc_num = 0; tpc_num < num_tpcs; tpc_num++) {
			list = nvgpu_netlist_get_tpc_compute_ctxsw_regs(g);
			for (i = 0; i < list->count; i++) {
				reg = &list->l[i];
				address = reg->addr;
				tpc_addr = pri_tpccs_addr_mask(g, address);
				base_address = gpc_base +
					(gpc_num * gpc_stride) +
					tpc_in_gpc_base +
					(tpc_num * tpc_in_gpc_stride);
				address = base_address + tpc_addr;
				if (is_tpc_layout_interleaved) {
					tpc_offset = (reg->index * num_tpcs) +
						(tpc_num * 4U);
				} else {
					tpc_offset = reg->index;
				}

				if (pri_addr == address) {
					*priv_offset = tpc_offset;
					return FOUND_IN_CTXSWBUF_PRIV_COMPUTE_REGLIST;
				}
			}
#ifdef CONFIG_NVGPU_GRAPHICS
			list = nvgpu_netlist_get_tpc_gfx_ctxsw_regs(g);
			for (i = 0; i < list->count; i++) {
				reg = &list->l[i];
				address = reg->addr;
				tpc_addr = pri_tpccs_addr_mask(g, address);
				base_address = gpc_base +
					(gpc_num * gpc_stride) +
					tpc_in_gpc_base +
					(tpc_num * tpc_in_gpc_stride);
				address = base_address + tpc_addr;
				if (is_tpc_layout_interleaved) {
					tpc_offset = (reg->index * num_tpcs) +
						(tpc_num * 4U);
				} else {
					tpc_offset = reg->index;
				}

				if (pri_addr == address) {
					*priv_offset = tpc_offset;
					return FOUND_IN_CTXSWBUF_PRIV_GFX_REGLIST;
				}
			}
#endif
		}
	} else if ((addr_type == CTXSW_ADDR_TYPE_EGPC) ||
		(addr_type == CTXSW_ADDR_TYPE_ETPC)) {
		if (g->ops.gr.get_egpc_base == NULL) {
			return -EINVAL;
		}

		for (tpc_num = 0; tpc_num < num_tpcs; tpc_num++) {
			list = nvgpu_netlist_get_etpc_compute_ctxsw_regs(g);
			for (i = 0; i < list->count; i++) {
				reg = &list->l[i];
				address = reg->addr;
				tpc_addr = pri_tpccs_addr_mask(g, address);
				base_address = g->ops.gr.get_egpc_base(g) +
					(gpc_num * gpc_stride) +
					tpc_in_gpc_base +
					(tpc_num * tpc_in_gpc_stride);
				address = base_address + tpc_addr;
				/*
				 * The data for the TPCs is interleaved in the context buffer.
				 * Example with num_tpcs = 2
				 * 0    1    2    3    4    5    6    7    8    9    10   11 ...
				 * 0-0  1-0  0-1  1-1  0-2  1-2  0-3  1-3  0-4  1-4  0-5  1-5 ...
				 */
				tpc_offset = (reg->index * num_tpcs) + (tpc_num * 4U);

				if (pri_addr == address) {
					*priv_offset = tpc_offset;
					nvgpu_log(g,
						gpu_dbg_fn | gpu_dbg_gpu_dbg,
						"egpc/etpc compute priv_offset=0x%#08x",
						*priv_offset);
					return FOUND_IN_CTXSWBUF_PRIV_COMPUTE_REGLIST;
				}
			}
#ifdef CONFIG_NVGPU_GRAPHICS
			list = nvgpu_netlist_get_etpc_gfx_ctxsw_regs(g);
			for (i = 0; i < list->count; i++) {
				reg = &list->l[i];
				address = reg->addr;
				tpc_addr = pri_tpccs_addr_mask(g, address);
				base_address = g->ops.gr.get_egpc_base(g) +
					(gpc_num * gpc_stride) +
					tpc_in_gpc_base +
					(tpc_num * tpc_in_gpc_stride);
				address = base_address + tpc_addr;
				/*
				 * The data for the TPCs is interleaved in the context buffer.
				 * Example with num_tpcs = 2
				 * 0    1    2    3    4    5    6    7    8    9    10   11 ...
				 * 0-0  1-0  0-1  1-1  0-2  1-2  0-3  1-3  0-4  1-4  0-5  1-5 ...
				 */
				tpc_offset = (reg->index * num_tpcs) + (tpc_num * 4U);

				if (pri_addr == address) {
					*priv_offset = tpc_offset;
					nvgpu_log(g,
						gpu_dbg_fn | gpu_dbg_gpu_dbg,
						"egpc/etpc gfx priv_offset=0x%#08x",
						*priv_offset);
					return FOUND_IN_CTXSWBUF_PRIV_GFX_REGLIST;
				}
			}
#endif
		}
	}


	/* Process the PPC segment. */
	if (addr_type == CTXSW_ADDR_TYPE_PPC) {
		for (ppc_num = 0; ppc_num < num_ppcs; ppc_num++) {
			list = nvgpu_netlist_get_ppc_compute_ctxsw_regs(g);
			for (i = 0; i < list->count; i++) {
				reg = &list->l[i];
				address = reg->addr;
				ppc_addr = pri_ppccs_addr_mask(address);
				base_address = gpc_base +
					(gpc_num * gpc_stride) +
					ppc_in_gpc_base +
					(ppc_num * ppc_in_gpc_stride);
				address = base_address + ppc_addr;
				/*
				 * The data for the PPCs is interleaved in the context buffer.
				 * Example with numPpcs = 2
				 * 0    1    2    3    4    5    6    7    8    9    10   11 ...
				 * 0-0  1-0  0-1  1-1  0-2  1-2  0-3  1-3  0-4  1-4  0-5  1-5 ...
				 */
				ppc_offset = (reg->index * num_ppcs) + (ppc_num * 4U);

				if (pri_addr == address)  {
					*priv_offset = ppc_offset;
					return FOUND_IN_CTXSWBUF_PRIV_COMPUTE_REGLIST;
				}
			}
#ifdef CONFIG_NVGPU_GRAPHICS
			list = nvgpu_netlist_get_ppc_gfx_ctxsw_regs(g);
			for (i = 0; i < list->count; i++) {
				reg = &list->l[i];
				address = reg->addr;
				ppc_addr = pri_ppccs_addr_mask(address);
				base_address = gpc_base +
					(gpc_num * gpc_stride) +
					ppc_in_gpc_base +
					(ppc_num * ppc_in_gpc_stride);
				address = base_address + ppc_addr;
				/*
				 * The data for the PPCs is interleaved in the context buffer.
				 * Example with numPpcs = 2
				 * 0    1    2    3    4    5    6    7    8    9    10   11 ...
				 * 0-0  1-0  0-1  1-1  0-2  1-2  0-3  1-3  0-4  1-4  0-5  1-5 ...
				 */
				ppc_offset = (reg->index * num_ppcs) + (ppc_num * 4U);

				if (pri_addr == address)  {
					*priv_offset = ppc_offset;
					return FOUND_IN_CTXSWBUF_PRIV_GFX_REGLIST;
				}
			}
#endif
		}
	}

	/* Process the GPC segment. */
	if (addr_type == CTXSW_ADDR_TYPE_GPC) {
		list = nvgpu_netlist_get_gpc_compute_ctxsw_regs(g);
		for (i = 0; i < list->count; i++) {
			reg = &list->l[i];

			address = reg->addr;
			gpc_addr = pri_gpccs_addr_mask(g, address);
			gpc_offset = reg->index;

			base_address = gpc_base + (gpc_num * gpc_stride);
			address = base_address + gpc_addr;

			if (pri_addr == address) {
				*priv_offset = gpc_offset;
				return FOUND_IN_CTXSWBUF_PRIV_COMPUTE_REGLIST;
			}
		}
#ifdef CONFIG_NVGPU_GRAPHICS
		list = nvgpu_netlist_get_gpc_gfx_ctxsw_regs(g);
		for (i = 0; i < list->count; i++) {
			reg = &list->l[i];

			address = reg->addr;
			gpc_addr = pri_gpccs_addr_mask(g, address);
			gpc_offset = reg->index;

			base_address = gpc_base + (gpc_num * gpc_stride);
			address = base_address + gpc_addr;

			if (pri_addr == address) {
				*priv_offset = gpc_offset;
				return FOUND_IN_CTXSWBUF_PRIV_GFX_REGLIST;
			}
		}
#endif
	}
	return -EINVAL;
}

/*
 * Calculate the offset of pri address within ctxsw buffer by going through the
 * various pri save segments.
 */
int gr_ga10b_find_priv_offset_in_buffer(struct gk20a *g, u32 addr,
					u32 *context_buffer,
					u32 context_buffer_size,
					u32 *priv_offset)
{
	int err;
	enum ctxsw_addr_type addr_type;
	u32 broadcast_flags = 0U;
	u32 gpc_num, tpc_num, ppc_num, be_num;
	u32 num_gpcs, num_tpcs, num_ppcs;
	u32 offset;
	u32 ppc_mask, reg_list_ppc_count;
	u32 *context;
	u32 segoffset, compute_segoffset;
	u32 graphics_segoffset;
	u32 main_hdr_size, fecs_hdr_size, gpccs_hdr_stride;
	u32 tpc_segment_pri_layout;
	bool is_tpc_layout_interleaved = false;

	err = g->ops.gr.decode_priv_addr(g, addr, &addr_type,
					&gpc_num, &tpc_num, &ppc_num, &be_num,
					&broadcast_flags);
	nvgpu_log(g, gpu_dbg_fn | gpu_dbg_gpu_dbg,
			"addr =0x%x addr_type = %d, broadcast_flags: %08x",
			addr, addr_type, broadcast_flags);
	if (err != 0) {
		return err;
	}

	context = context_buffer;
	if (!g->ops.gr.ctxsw_prog.check_main_image_header_magic(context)) {
		nvgpu_err(g, "invalid main header: magic value");
		return -EINVAL;
	}

	main_hdr_size = g->ops.gr.ctxsw_prog.hw_get_main_header_size();
	fecs_hdr_size = g->ops.gr.ctxsw_prog.hw_get_fecs_header_size();
	gpccs_hdr_stride = g->ops.gr.ctxsw_prog.hw_get_gpccs_header_stride();
	num_gpcs = g->ops.gr.ctxsw_prog.get_num_gpcs(context);
	/*
	 * Determine the layout of the TPC priv save segment. It can either
	 * be interleaved or migration. In case of interleaved, the registers
	 * will be sorted by address first followed by TPC number, migration
	 * layout is does the exact opposite.
	 */
	tpc_segment_pri_layout = g->ops.gr.ctxsw_prog.get_tpc_segment_pri_layout(g, context_buffer);
	nvgpu_assert(tpc_segment_pri_layout != ctxsw_prog_main_tpc_segment_pri_layout_v_invalid_v());
	is_tpc_layout_interleaved = (tpc_segment_pri_layout ==
			ctxsw_prog_main_tpc_segment_pri_layout_v_interleaved_v());

	/*
	 * Check in extended buffer segment of ctxsw buffer. If found, return
	 * else continue on.
	 */
	err = gr_gk20a_find_priv_offset_in_ext_buffer(g,
				      addr, context_buffer,
				      context_buffer_size, priv_offset);
	if (err == 0) {
		nvgpu_log(g, gpu_dbg_fn | gpu_dbg_gpu_dbg,
			"offset found in Ext buffer");
		return err;
	}

	/* Parse the FECS local header. */
	context += (main_hdr_size >> 2);
	if (!g->ops.gr.ctxsw_prog.check_local_header_magic(context)) {
		nvgpu_err(g,
			   "Invalid FECS local header: magic value");
		return -EINVAL;
	}

	if ((addr_type == CTXSW_ADDR_TYPE_SYS) ||
		(addr_type == CTXSW_ADDR_TYPE_ROP)) {
		compute_segoffset =
			g->ops.gr.ctxsw_prog.get_compute_sysreglist_offset(context);
		graphics_segoffset =
			g->ops.gr.ctxsw_prog.get_gfx_sysreglist_offset(context);
		nvgpu_log(g, gpu_dbg_gpu_dbg, "sys_segment_offsets(0x%x, 0x%x)",
			compute_segoffset, graphics_segoffset);

		err = g->ops.gr.process_context_buffer_priv_segment(g, addr_type,
				addr, 0, 0, 0, 0, &offset);
		if (err < 0) {
			return err;
		}
		segoffset = (err == FOUND_IN_CTXSWBUF_PRIV_COMPUTE_REGLIST) ?
			compute_segoffset : graphics_segoffset;
		*priv_offset = (segoffset + offset);
		return 0;

	} else if (addr_type == CTXSW_ADDR_TYPE_LTS_MAIN) {
		segoffset = g->ops.gr.ctxsw_prog.get_ltsreglist_offset(context);
		nvgpu_log(g, gpu_dbg_gpu_dbg, "lts_segment_offset(0x%x)",
				segoffset);

		err = g->ops.gr.process_context_buffer_priv_segment(g, addr_type,
				addr, 0, 0, 0, 0, &offset);
		if (err < 0) {
			return err;
		}
		*priv_offset = (segoffset + offset);
		return 0;
	}

	if ((gpc_num + 1U) > num_gpcs)  {
		nvgpu_err(g,
			   "GPC %d not in this context buffer.",
			   gpc_num);
		return -EINVAL;
	}

	/*
	 * Skip ahead to the relevant gpccs segment.
	 */
	context += (fecs_hdr_size >> BYTE_TO_DW_SHIFT) +
		((gpc_num * gpccs_hdr_stride) >> BYTE_TO_DW_SHIFT);
	if (!g->ops.gr.ctxsw_prog.check_local_header_magic(context)) {
		nvgpu_err(g,
			   "Invalid GPCCS header: magic value");
		return -EINVAL;
	}

	num_tpcs = g->ops.gr.ctxsw_prog.get_num_tpcs(context);
	if ((tpc_num + 1U) > num_tpcs) {
		nvgpu_err(g, "GPC %d TPC %d not in this context buffer.",
				gpc_num, tpc_num);
		return -EINVAL;
	}

	err = gr_gk20a_determine_ppc_configuration(g, context, &num_ppcs,
			&ppc_mask, &reg_list_ppc_count);
	if (err != 0) {
		nvgpu_err(g, "determine ppc configuration failed");
		return err;
	}

	if (addr_type == CTXSW_ADDR_TYPE_GPC) {
		compute_segoffset =
			g->ops.gr.ctxsw_prog.get_compute_gpcreglist_offset(context);
		graphics_segoffset =
			g->ops.gr.ctxsw_prog.get_gfx_gpcreglist_offset(context);
	} else if (addr_type == CTXSW_ADDR_TYPE_PPC) {
		compute_segoffset =
			g->ops.gr.ctxsw_prog.get_compute_ppcreglist_offset(context);
		graphics_segoffset =
			g->ops.gr.ctxsw_prog.get_gfx_ppcreglist_offset(context);
	} else if (addr_type == CTXSW_ADDR_TYPE_TPC) {
		/*
		 * Incase of interleaved TPC layout, all TPC registers will be
		 * saved contiguously starting from TPC0 segment address,
		 * whereas, in migration layout, registers of each TPC will
		 * be stored in separate segments based on the tpc number.
		 * Hence, for interleaved layout the segment start address will
		 * be a constant for all TPC registers i.e. the segment address
		 * of TPC0.
		 */
		if (is_tpc_layout_interleaved) {
			tpc_num = 0;

		}
		compute_segoffset =
			g->ops.gr.ctxsw_prog.get_compute_tpcreglist_offset(context, tpc_num);
		graphics_segoffset =
			g->ops.gr.ctxsw_prog.get_gfx_tpcreglist_offset(context, tpc_num);
	} else if (addr_type == CTXSW_ADDR_TYPE_ETPC) {
		compute_segoffset =
			g->ops.gr.ctxsw_prog.get_compute_etpcreglist_offset(context);
		graphics_segoffset =
			g->ops.gr.ctxsw_prog.get_gfx_etpcreglist_offset(context);
	} else {
		nvgpu_err(g, "invalid addr_type(0x%x)", addr_type);
		return -EINVAL;
	}
	nvgpu_log(g, gpu_dbg_fn | gpu_dbg_gpu_dbg,
		"gpccs_segment_offset(0x%x, 0x%x)", compute_segoffset,
		graphics_segoffset);

	err = g->ops.gr.process_context_buffer_priv_segment(g, addr_type,
			addr, gpc_num, num_tpcs, num_ppcs, ppc_mask, &offset);
	if (err < 0) {
		return err;
	}

	segoffset = (err == FOUND_IN_CTXSWBUF_PRIV_COMPUTE_REGLIST) ? compute_segoffset :
		graphics_segoffset;
	*priv_offset = (segoffset + offset);
	return 0;
}

static const u32 hwpm_cau_init_data[] =
{
	/* This list is autogenerated. Do not edit. */
	0x00419980,
	0x00000000,
	0x00419988,
	0x00000000,
	0x0041998c,
	0x00000000,
	0x00419990,
	0x00000000,
	0x00419994,
	0x00000000,
	0x00419998,
	0x00000000,
	0x0041999c,
	0x00000000,
	0x004199a4,
	0x00000001,
};

const u32 *ga10b_gr_get_hwpm_cau_init_data(u32 *count)
{
	*count = sizeof(hwpm_cau_init_data) / sizeof(hwpm_cau_init_data[0]);
	return hwpm_cau_init_data;
}

int ga10b_gr_set_sched_wait_for_errbar(struct gk20a *g,
	struct nvgpu_channel *ch, bool enable)
{
	struct nvgpu_dbg_reg_op ctx_ops = {
		.op = REGOP(WRITE_32),
		.type = REGOP(TYPE_GR_CTX),
		.offset = gr_gpcs_pri_tpcs_sm_sch_macro_sched_r(),
		.value_lo = enable ?
		gr_gpcs_pri_tpcs_sm_sch_macro_sched_exit_wait_for_errbar_enabled_f() :
		gr_gpcs_pri_tpcs_sm_sch_macro_sched_exit_wait_for_errbar_disabled_f(),
	};
	int err;
	struct nvgpu_tsg *tsg = nvgpu_tsg_from_ch(ch);
	u32 flags = NVGPU_REG_OP_FLAG_MODE_ALL_OR_NONE;

	if (tsg != NULL) {
		err = g->ops.regops.exec_regops(g, tsg, &ctx_ops, 1, 1, 0, &flags);
		if (err != 0) {
			nvgpu_err(g, "update implicit ERRBAR failed");
		}
	} else {
		nvgpu_err(g, "chid: %d is not bound to tsg", ch->chid);
		return -EINVAL;
	}
	return err;
}

#endif /* CONFIG_NVGPU_DEBUGGER */

#ifdef CONFIG_NVGPU_HAL_NON_FUSA
void ga10b_gr_vab_reserve(struct gk20a *g, u32 vab_reg, u32 num_range_checkers,
	struct nvgpu_vab_range_checker *vab_range_checker)
{
	/*
	 * configure range checkers in GPC
	 */

	u32 i = 0U;
	u32 granularity_shift_bits_base = 16U; /* log(64KB) */
	u32 granularity_shift_bits = 0U;

	nvgpu_log_fn(g, " ");

	for (i = 0U; i < num_range_checkers; i++) {
		granularity_shift_bits = nvgpu_safe_sub_u32(
			vab_range_checker[i].granularity_shift,
			granularity_shift_bits_base);

		nvgpu_writel(g, gr_gpcs_mmu_vidmem_access_bit_start_addr_hi_r(i),
			U32(vab_range_checker[i].start_phys_addr >> 32U));

		nvgpu_writel(g, gr_gpcs_mmu_vidmem_access_bit_start_addr_lo_r(i),
			(u32)(vab_range_checker[i].start_phys_addr &
			gr_gpcs_mmu_vidmem_access_bit_start_addr_lo_val_m()) |
			gr_gpcs_mmu_vidmem_access_bit_start_addr_lo_granularity_f(
				granularity_shift_bits));
	}

	/* Setup VAB */
	nvgpu_writel(g, gr_gpcs_mmu_vidmem_access_bit_r(), vab_reg);
}

void ga10b_gr_vab_configure(struct gk20a *g, u32 vab_reg)
{
	nvgpu_writel(g, gr_gpcs_mmu_vidmem_access_bit_r(), vab_reg);
}

#endif /* CONFIG_NVGPU_HAL_NON_FUSA */
