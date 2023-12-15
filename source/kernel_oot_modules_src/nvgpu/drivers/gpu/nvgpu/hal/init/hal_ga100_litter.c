/*
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

#include <nvgpu/gk20a.h>
#include <nvgpu/class.h>

#include <nvgpu/hw/ga100/hw_proj_ga100.h>

#include "hal_ga100_litter.h"

u32 ga100_get_litter_value(struct gk20a *g, int value)
{
	u32 ret = 0;

	switch (value) {
	case GPU_LIT_NUM_GPCS:
		ret = proj_scal_litter_num_gpcs_v();
		break;
	case GPU_LIT_NUM_PES_PER_GPC:
		ret = proj_scal_litter_num_pes_per_gpc_v();
		break;
	case GPU_LIT_NUM_ZCULL_BANKS:
		ret = proj_scal_litter_num_zcull_banks_v();
		break;
	case GPU_LIT_NUM_TPC_PER_GPC:
		ret = proj_scal_litter_num_tpc_per_gpc_v();
		break;
	case GPU_LIT_NUM_SM_PER_TPC:
		ret = proj_scal_litter_num_sm_per_tpc_v();
		break;
	case GPU_LIT_NUM_FBPS:
		ret = proj_scal_litter_num_fbps_v();
		break;
	case GPU_LIT_GPC_BASE:
		ret = proj_gpc_base_v();
		break;
	case GPU_LIT_GPC_STRIDE:
		ret = proj_gpc_stride_v();
		break;
	case GPU_LIT_GPC_SHARED_BASE:
		ret = proj_gpc_shared_base_v();
		break;
	case GPU_LIT_GPC_ADDR_WIDTH:
		ret = proj_gpc_addr_width_v();
		break;
	case GPU_LIT_TPC_ADDR_WIDTH:
		ret = proj_tpc_addr_width_v();
		break;
	case GPU_LIT_TPC_IN_GPC_BASE:
		ret = proj_tpc_in_gpc_base_v();
		break;
	case GPU_LIT_TPC_IN_GPC_STRIDE:
		ret = proj_tpc_in_gpc_stride_v();
		break;
	case GPU_LIT_TPC_IN_GPC_SHARED_BASE:
		ret = proj_tpc_in_gpc_shared_base_v();
		break;
	case GPU_LIT_PPC_IN_GPC_BASE:
		ret = proj_ppc_in_gpc_base_v();
		break;
	case GPU_LIT_PPC_IN_GPC_STRIDE:
		ret = proj_ppc_in_gpc_stride_v();
		break;
	case GPU_LIT_PPC_IN_GPC_SHARED_BASE:
		ret = proj_ppc_in_gpc_shared_base_v();
		break;
	case GPU_LIT_ROP_BASE:
		ret = proj_rop_base_v();
		break;
	case GPU_LIT_ROP_STRIDE:
		ret = proj_rop_stride_v();
		break;
	case GPU_LIT_ROP_SHARED_BASE:
		ret = proj_rop_shared_base_v();
		break;
	case GPU_LIT_HOST_NUM_ENGINES:
		ret = proj_host_num_engines_v();
		break;
	case GPU_LIT_HOST_NUM_PBDMA:
		ret = proj_host_num_pbdma_v();
		break;
	case GPU_LIT_LTC_STRIDE:
		ret = proj_ltc_stride_v();
		break;
	case GPU_LIT_LTS_STRIDE:
		ret = proj_lts_stride_v();
		break;
	case GPU_LIT_NUM_FBPAS:
		ret = proj_scal_litter_num_fbpas_v();
		break;
	case GPU_LIT_FBPA_SHARED_BASE:
		ret = proj_fbpa_shared_base_v();
		break;
	case GPU_LIT_FBPA_BASE:
		ret = proj_fbpa_base_v();
		break;
	case GPU_LIT_FBPA_STRIDE:
		ret = proj_fbpa_stride_v();
		break;
	case GPU_LIT_SM_PRI_STRIDE:
		ret = proj_sm_stride_v();
		break;
	case GPU_LIT_SMPC_PRI_BASE:
		ret = proj_smpc_base_v();
		break;
	case GPU_LIT_SMPC_PRI_SHARED_BASE:
		ret = proj_smpc_shared_base_v();
		break;
	case GPU_LIT_SMPC_PRI_UNIQUE_BASE:
		ret = proj_smpc_unique_base_v();
		break;
	case GPU_LIT_SMPC_PRI_STRIDE:
		ret = proj_smpc_stride_v();
		break;
	case GPU_LIT_SM_UNIQUE_BASE:
		ret = proj_sm_unique_base_v();
		break;
	case GPU_LIT_SM_SHARED_BASE:
		ret = proj_sm_shared_base_v();
		break;
	case GPU_LIT_NUM_LTC_LTS_SETS:
		ret = proj_scal_litter_num_ltc_lts_sets_v();
		break;
	case GPU_LIT_NUM_LTC_LTS_WAYS:
		ret = proj_scal_litter_num_ltc_lts_ways_v();
		break;
#ifdef CONFIG_NVGPU_GRAPHICS
	case GPU_LIT_TWOD_CLASS:
		ret = FERMI_TWOD_A;
		break;
	case GPU_LIT_THREED_CLASS:
		break;
#endif
	case GPU_LIT_COMPUTE_CLASS:
		ret = AMPERE_COMPUTE_A;
		break;
	case GPU_LIT_GPFIFO_CLASS:
		ret = AMPERE_CHANNEL_GPFIFO_A;
		break;
	case GPU_LIT_I2M_CLASS:
		ret = KEPLER_INLINE_TO_MEMORY_B;
		break;
	case GPU_LIT_DMA_COPY_CLASS:
		ret = AMPERE_DMA_COPY_A;
		break;
	case GPU_LIT_GPC_PRIV_STRIDE:
		ret = proj_gpc_priv_stride_v();
		break;
#ifdef CONFIG_NVGPU_DEBUGGER
	case GPU_LIT_PERFMON_PMMGPCTPCA_DOMAIN_START:
		ret = 2;
		break;
	case GPU_LIT_PERFMON_PMMGPCTPCB_DOMAIN_START:
		ret = 8;
		break;
	case GPU_LIT_PERFMON_PMMGPCTPC_DOMAIN_COUNT:
		ret = 6;
		break;
	case GPU_LIT_PERFMON_PMMFBP_LTC_DOMAIN_START:
		ret = 2;
		break;
	case GPU_LIT_PERFMON_PMMFBP_LTC_DOMAIN_COUNT:
		ret = 8;
		break;
	case GPU_LIT_PERFMON_PMMFBP_ROP_DOMAIN_START:
		ret = 10;
		break;
	case GPU_LIT_PERFMON_PMMFBP_ROP_DOMAIN_COUNT:
		ret = 2;
		break;
#endif
	case GPU_LIT_MAX_RUNLISTS_SUPPORTED:
		ret = 24U;
		break;
	default:
		nvgpu_err(g, "Missing definition %d", value);
		BUG();
		break;
	}

	return ret;
}

