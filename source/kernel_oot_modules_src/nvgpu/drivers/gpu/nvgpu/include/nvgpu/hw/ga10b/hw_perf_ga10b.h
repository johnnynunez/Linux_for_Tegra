/* SPDX-License-Identifier: MIT */
/*
 * SPDX-FileCopyrightText: Copyright (c) 2019-2023, NVIDIA CORPORATION & AFFILIATES.
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
/*
 * Function/Macro naming determines intended use:
 *
 *     <x>_r(void) : Returns the offset for register <x>.
 *
 *     <x>_o(void) : Returns the offset for element <x>.
 *
 *     <x>_w(void) : Returns the word offset for word (4 byte) element <x>.
 *
 *     <x>_<y>_s(void) : Returns size of field <y> of register <x> in bits.
 *
 *     <x>_<y>_f(u32 v) : Returns a value based on 'v' which has been shifted
 *         and masked to place it at field <y> of register <x>.  This value
 *         can be |'d with others to produce a full register value for
 *         register <x>.
 *
 *     <x>_<y>_m(void) : Returns a mask for field <y> of register <x>.  This
 *         value can be ~'d and then &'d to clear the value of field <y> for
 *         register <x>.
 *
 *     <x>_<y>_<z>_f(void) : Returns the constant value <z> after being shifted
 *         to place it at field <y> of register <x>.  This value can be |'d
 *         with others to produce a full register value for <x>.
 *
 *     <x>_<y>_v(u32 r) : Returns the value of field <y> from a full register
 *         <x> value 'r' after being shifted to place its LSB at bit 0.
 *         This value is suitable for direct comparison with other unshifted
 *         values appropriate for use in field <y> of register <x>.
 *
 *     <x>_<y>_<z>_v(void) : Returns the constant value for <z> defined for
 *         field <y> of register <x>.  This value is suitable for direct
 *         comparison with unshifted values appropriate for use in field <y>
 *         of register <x>.
 */
#ifndef NVGPU_HW_PERF_GA10B_H
#define NVGPU_HW_PERF_GA10B_H

#include <nvgpu/types.h>
#include <nvgpu/static_analysis.h>

#define perf_pmmgpc_perdomain_offset_v()                           (0x00000200U)
#define perf_pmmsys_perdomain_offset_v()                           (0x00000200U)
#define perf_pmmgpc_base_v()                                       (0x00180000U)
#define perf_pmmgpc_extent_v()                                     (0x00183fffU)
#define perf_pmmsys_base_v()                                       (0x00260000U)
#define perf_pmmsys_extent_v()                                     (0x00263fffU)
#define perf_pmmfbp_base_v()                                       (0x00200000U)
#define perf_pmmfbp_extent_v()                                     (0x00203fffU)
#define perf_pmmfbprouter_base_v()                                 (0x00246000U)
#define perf_pmmfbprouter_extent_v()                               (0x002461ffU)
#define perf_pmmgpcrouter_base_v()                                 (0x00244000U)
#define perf_pmmgpcrouter_extent_v()                               (0x002441ffU)
#define perf_pmasys_control_r()                                    (0x0024a000U)
#define perf_pmasys_channel_control_user_r(i)\
		(nvgpu_safe_add_u32(0x0024a620U, nvgpu_safe_mult_u32((i), 384U)))
#define perf_pmasys_channel_control_user__size_1_v()               (0x00000001U)
#define perf_pmasys_channel_control_user_stream_m()            (U32(0x1U) << 0U)
#define perf_pmasys_channel_control_user_stream_enable_f()                (0x1U)
#define perf_pmasys_channel_control_user_stream_disable_f()               (0x0U)
#define perf_pmasys_channel_control_user_update_bytes_m()     (U32(0x1U) << 31U)
#define perf_pmasys_channel_control_user_update_bytes_doit_f()     (0x80000000U)
#define perf_pmasys_channel_control_user_update_bytes_init_f()            (0x0U)
#define perf_pmasys_channel_control_user_membuf_clear_status_m()\
				(U32(0x1U) << 1U)
#define perf_pmasys_channel_control_user_membuf_clear_status_doit_f()     (0x2U)
#define perf_pmasys_channel_control_user_membuf_clear_status_init_f()     (0x0U)
#define perf_pmasys_channel_control_user_flush_coalesce_fifo_m()\
				(U32(0x1U) << 2U)
#define perf_pmasys_channel_control_user_flush_coalesce_fifo_init_f()     (0x0U)
#define perf_pmasys_channel_control_user_send_bind_m()         (U32(0x1U) << 3U)
#define perf_pmasys_channel_control_user_send_bind_init_f()               (0x0U)
#define perf_pmasys_channel_control_user_reset_data_fifo_m()  (U32(0x1U) << 25U)
#define perf_pmasys_channel_control_user_reset_data_fifo_init_f()         (0x0U)
#define perf_pmasys_channel_status_secure_r(i)\
		(nvgpu_safe_add_u32(0x0024a610U, nvgpu_safe_mult_u32((i), 384U)))
#define perf_pmasys_channel_status_secure__size_1_v()              (0x00000001U)
#define perf_pmasys_channel_status_secure_membuf_status_overflowed_f()    (0x1U)
#define perf_pmasys_channel_mem_block_r(i)\
		(nvgpu_safe_add_u32(0x0024a638U, nvgpu_safe_mult_u32((i), 4U)))
#define perf_pmasys_channel_mem_block__size_1_v()                  (0x00000001U)
#define perf_pmasys_channel_mem_block_base_f(v)    ((U32(v) & 0xfffffffU) << 0U)
#define perf_pmasys_channel_mem_block_target_f(v)       ((U32(v) & 0x3U) << 28U)
#define perf_pmasys_channel_mem_block_target_lfb_f()                      (0x0U)
#define perf_pmasys_channel_mem_block_target_sys_coh_f()           (0x20000000U)
#define perf_pmasys_channel_mem_block_target_sys_ncoh_f()          (0x30000000U)
#define perf_pmasys_channel_mem_block_valid_true_f()               (0x80000000U)
#define perf_pmasys_channel_mem_block_valid_false_f()                     (0x0U)
#define perf_pmasys_channel_outbase_r(i)\
		(nvgpu_safe_add_u32(0x0024a644U, nvgpu_safe_mult_u32((i), 4U)))
#define perf_pmasys_channel_outbase__size_1_v()                    (0x00000001U)
#define perf_pmasys_channel_outbaseupper_r(i)\
		(nvgpu_safe_add_u32(0x0024a648U, nvgpu_safe_mult_u32((i), 4U)))
#define perf_pmasys_channel_outbaseupper__size_1_v()               (0x00000001U)
#define perf_pmasys_channel_outbaseupper_ptr_f(v)       ((U32(v) & 0xffU) << 0U)
#define perf_pmasys_channel_outsize_r(i)\
		(nvgpu_safe_add_u32(0x0024a64cU, nvgpu_safe_mult_u32((i), 4U)))
#define perf_pmasys_channel_outsize__size_1_v()                    (0x00000001U)
#define perf_pmasys_channel_mem_head_r(i)\
		(nvgpu_safe_add_u32(0x0024a650U, nvgpu_safe_mult_u32((i), 4U)))
#define perf_pmasys_channel_mem_head__size_1_v()                   (0x00000001U)
#define perf_pmasys_channel_mem_bytes_r(i)\
		(nvgpu_safe_add_u32(0x0024a654U, nvgpu_safe_mult_u32((i), 4U)))
#define perf_pmasys_channel_mem_bytes__size_1_v()                  (0x00000001U)
#define perf_pmasys_channel_mem_bump_r(i)\
		(nvgpu_safe_add_u32(0x0024a624U, nvgpu_safe_mult_u32((i), 4U)))
#define perf_pmasys_channel_mem_bump__size_1_v()                   (0x00000001U)
#define perf_pmasys_channel_mem_bytes_addr_r(i)\
		(nvgpu_safe_add_u32(0x0024a658U, nvgpu_safe_mult_u32((i), 4U)))
#define perf_pmasys_channel_mem_bytes_addr__size_1_v()             (0x00000001U)
#define perf_pmasys_channel_mem_bytes_addr_ptr_f(v)\
				((U32(v) & 0x3fffffffU) << 2U)
#define perf_pmasys_channel_mem_bytes_addr_ptr_b()                          (2U)
#define perf_pmasys_enginestatus_r()                               (0x0024a75cU)
#define perf_pmasys_enginestatus_rbufempty_v(r)             (((r) >> 4U) & 0x1U)
#define perf_pmasys_enginestatus_rbufempty_empty_v()               (0x00000001U)
#define perf_pmasys_enginestatus_rbufempty_empty_f()                     (0x10U)
#define perf_pmasys_enginestatus_status_v(r)                (((r) >> 0U) & 0x7U)
#define perf_pmasys_enginestatus_status_empty_v()                  (0x00000000U)
#define perf_pmasys_controlreg_r()                                 (0x0024a03cU)
#define perf_pmasys_controlreg_legacy_mode_m()                 (U32(0x1U) << 0U)
#define perf_pmasys_controlreg_legacy_mode_enable_f()                     (0x0U)
#define perf_pmasys_controlreg_legacy_mode_disable_f()                    (0x1U)
#define perf_pmasys_controlb_r()                                   (0x0024a070U)
#define perf_pmasys_controlb_coalesce_timeout_cycles_m()       (U32(0x7U) << 4U)
#define perf_pmasys_controlb_coalesce_timeout_cycles__prod_f()           (0x40U)
#define perf_pmasys_controlb_coalesce_timeout_cycles_64_f()              (0x20U)
#define perf_pmasys_controlb_mbu_cya_smb_m()                   (U32(0x1U) << 0U)
#define perf_pmasys_controlb_mbu_cya_smb_disable_f()                      (0x0U)
#define perf_pmasys_controlb_mbu_cya_ss_m()                    (U32(0x1U) << 1U)
#define perf_pmasys_controlb_mbu_cya_ss_disable_f()                       (0x0U)
#define perf_pmasys_controlb_keep_latest_m()                   (U32(0x1U) << 2U)
#define perf_pmasys_controlb_keep_latest_disable_f()                      (0x0U)
#define perf_pmasys_controlb_fault_nack_cya_m()                (U32(0x1U) << 3U)
#define perf_pmasys_controlb_fault_nack_cya_disable_f()                   (0x0U)
#define perf_pmasys_channel_config_user_r(i)\
		(nvgpu_safe_add_u32(0x0024a640U, nvgpu_safe_mult_u32((i), 384U)))
#define perf_pmasys_channel_config_user__size_1_v()                (0x00000001U)
#define perf_pmasys_channel_config_user_coalesce_timeout_cycles_m()\
				(U32(0x7U) << 4U)
#define perf_pmasys_channel_config_user_coalesce_timeout_cycles__prod_f()\
				(0x40U)
#define perf_pmasys_channel_config_user_coalesce_timeout_cycles_64_f()   (0x20U)
#define perf_pmasys_channel_config_user_keep_latest_m()        (U32(0x1U) << 2U)
#define perf_pmasys_channel_config_user_keep_latest_disable_f()           (0x0U)
#define perf_pmmsys_engine_sel_r(i)\
		(nvgpu_safe_add_u32(0x0026006cU, nvgpu_safe_mult_u32((i), 512U)))
#define perf_pmmsys_engine_sel__size_1_v()                         (0x0000000cU)
#define perf_pmmfbp_engine_sel_r(i)\
		(nvgpu_safe_add_u32(0x0020006cU, nvgpu_safe_mult_u32((i), 512U)))
#define perf_pmmfbp_engine_sel__size_1_v()                         (0x00000005U)
#define perf_pmmgpc_engine_sel_r(i)\
		(nvgpu_safe_add_u32(0x0018006cU, nvgpu_safe_mult_u32((i), 512U)))
#define perf_pmmgpc_engine_sel__size_1_v()                         (0x00000010U)
#define perf_pmmsys_control_r(i)\
		(nvgpu_safe_add_u32(0x0026009cU, nvgpu_safe_mult_u32((i), 512U)))
#define perf_pmmfbp_fbps_control_r(i)\
		(nvgpu_safe_add_u32(0x0027c09cU, nvgpu_safe_mult_u32((i), 512U)))
#define perf_pmmgpc_gpcs_control_r(i)\
		(nvgpu_safe_add_u32(0x0027809cU, nvgpu_safe_mult_u32((i), 512U)))
#define perf_pmmsysrouter_global_cntrl_r()                         (0x00248000U)
#define perf_pmmsysrouter_global_cntrl_hs_stream_enable_m()    (U32(0x1U) << 8U)
#define perf_pmmsysrouter_global_cntrl_hs_stream_enable_true_f()        (0x100U)
#define perf_pmmsysrouter_global_cntrl_hs_stream_enable_false_f()         (0x0U)
#define perf_pmmgpcrouter_global_cntrl_r()                         (0x00244000U)
#define perf_pmmfbprouter_global_cntrl_r()                         (0x00246000U)
#define perf_pmmsysrouter_hs_config_r()                            (0x00248150U)
#define perf_pmmgpcrouter_hs_config_r()                            (0x00244150U)
#define perf_pmmfbprouter_hs_config_r()                            (0x00246150U)
#define perf_pmmsysrouter_perfmonstatus_r()                        (0x00248014U)
#define perf_pmmsysrouter_enginestatus_r()                         (0x00248010U)
#define perf_pmmsysrouter_enginestatus_status_v(r)          (((r) >> 0U) & 0x7U)
#define perf_pmmsysrouter_enginestatus_status_empty_v()            (0x00000000U)
#define perf_pmmsysrouter_enginestatus_status_quiescent_v()        (0x00000003U)
#define perf_pmmgpcrouter_perfmonstatus_r()                        (0x00244014U)
#define perf_pmmgpcrouter_enginestatus_r()                         (0x00244010U)
#define perf_pmmfbprouter_perfmonstatus_r()                        (0x00246014U)
#define perf_pmmfbprouter_enginestatus_r()                         (0x00246010U)
#define perf_pmasys_trigger_config_user_r(i)\
		(nvgpu_safe_add_u32(0x0024a694U, nvgpu_safe_mult_u32((i), 384U)))
#define perf_pmasys_trigger_config_user__size_1_v()                (0x00000001U)
#define perf_pmasys_trigger_config_user_pma_pulse_m()          (U32(0x1U) << 0U)
#define perf_pmasys_trigger_config_user_pma_pulse_disable_f()             (0x0U)
#define perf_pmasys_trigger_config_user_pma_pulse_window_m()   (U32(0x1U) << 1U)
#define perf_pmasys_trigger_config_user_pma_pulse_window_inside_f()       (0x0U)
#define perf_pmasys_trigger_config_user_pma_pulse_source_m()   (U32(0x3U) << 2U)
#define perf_pmasys_trigger_config_user_pma_pulse_source_internal_f()     (0x0U)
#define perf_pmasys_trigger_config_user_pma_pulse_cntr_m()     (U32(0x3U) << 4U)
#define perf_pmasys_trigger_config_user_pma_pulse_cntr_one_f()            (0x0U)
#define perf_pmasys_trigger_config_user_record_stream_m()      (U32(0x1U) << 6U)
#define perf_pmasys_trigger_config_user_record_stream_disable_f()         (0x0U)
#define perf_pmasys_config1_r(i)\
		(nvgpu_safe_add_u32(0x0024a62cU, nvgpu_safe_mult_u32((i), 384U)))
#define perf_pmasys_config1__size_1_v()                            (0x00000001U)
#define perf_pmasys_config1_bf_20_20_m()                      (U32(0x1U) << 20U)
#define perf_pmasys_config1_bf_20_20_disable_f()                     (0x100000U)
#define perf_pmasys_config1_bf_21_21_m()                      (U32(0x1U) << 21U)
#define perf_pmasys_config1_bf_21_21_enable_f()                      (0x200000U)
#define perf_pmasys_config2_r(i)\
		(nvgpu_safe_add_u32(0x0024a630U, nvgpu_safe_mult_u32((i), 384U)))
#define perf_pmasys_config2__size_1_v()                            (0x00000001U)
#define perf_pmasys_config2_bf_0_0_m()                         (U32(0x1U) << 0U)
#define perf_pmasys_config2_bf_0_0_disable_f()                            (0x0U)
#define perf_pmasys_pulse_timebaseset_r()                          (0x0024a698U)
#define perf_pmasys_pulse_timebasecnt_r()                          (0x0024a69cU)
#define perf_pmasys_record_start_triggercnt_r()                    (0x0024a724U)
#define perf_pmasys_record_stop_triggercnt_r()                     (0x0024a728U)
#define perf_pmasys_record_total_triggercnt_r()                    (0x0024a72cU)
#define perf_pmasys_trigger_global_r()                             (0x0024a008U)
#define perf_pmasys_router_config0_r()                             (0x0024a68cU)
#define perf_pmasys_router_config1_r()                             (0x0024a690U)
#define perf_pmasys_config3_r(i)\
		(nvgpu_safe_add_u32(0x0024a63cU, nvgpu_safe_mult_u32((i), 384U)))
#define perf_pmasys_config3__size_1_v()                            (0x00000001U)
#define perf_pmasys_config3_bf_1_1_m()                         (U32(0x1U) << 1U)
#define perf_pmasys_config3_bf_1_1_disable_f()                            (0x0U)
#define perf_pmasys_config3_bf_2_2_m()                         (U32(0x1U) << 2U)
#define perf_pmasys_config3_bf_2_2_disable_f()                            (0x0U)
#define perf_pmasys_config3_bf_3_3_m()                         (U32(0x1U) << 3U)
#define perf_pmasys_config3_bf_3_3_disable_f()                            (0x0U)
#define perf_pmasys_channel_control_r(i)\
		(nvgpu_safe_add_u32(0x0024a730U, nvgpu_safe_mult_u32((i), 4U)))
#define perf_pmasys_channel_control__size_1_v()                    (0x00000001U)
#define perf_pmasys_channel_control_stream_m()                 (U32(0x1U) << 0U)
#define perf_pmasys_channel_control_stream_disable_f()                    (0x0U)
#define perf_pmasys_channel_control_pmactxsw_mode_m()          (U32(0x1U) << 1U)
#define perf_pmasys_channel_control_pmactxsw_mode_enable_f()              (0x0U)
#define perf_pmasys_channel_control_pma_record_stream_m()      (U32(0x1U) << 8U)
#define perf_pmasys_channel_control_pma_record_stream_disable_f()         (0x0U)
#define perf_pmasys_channel_control_fe2all_ctxsw_freeze_enable_m()\
				(U32(0x1U) << 22U)
#define perf_pmasys_channel_control_fe2all_ctxsw_freeze_enable_true_f()\
				(0x400000U)
#define perf_pmasys_channel_control_pma_ctxsw_freeze_m()      (U32(0x1U) << 23U)
#define perf_pmasys_channel_control_pma_ctxsw_freeze_false_f()            (0x0U)
#define perf_pmasys_sys_trigger_start_mask_r()                     (0x0024a66cU)
#define perf_pmasys_sys_trigger_start_maskb_r()                    (0x0024a670U)
#define perf_pmasys_sys_trigger_stop_mask_r()                      (0x0024a684U)
#define perf_pmasys_sys_trigger_stop_maskb_r()                     (0x0024a688U)
#define perf_pmasys_sys_trigger_config_tesla_mode_r()              (0x0024a6b0U)
#define perf_pmasys_sys_trigger_config_tesla_modeb_r()             (0x0024a6b4U)
#define perf_pmasys_sys_trigger_config_mixed_mode_r()              (0x0024a6c8U)
#define perf_pmasys_sys_trigger_config_mixed_modeb_r()             (0x0024a6ccU)
#define perf_pmasys_sys_trigger_start_r()                          (0x0024a6e0U)
#define perf_pmasys_sys_trigger_startb_r()                         (0x0024a6e4U)
#define perf_pmasys_sys_trigger_status_r()                         (0x0024a710U)
#define perf_pmasys_sys_trigger_statusb_r()                        (0x0024a714U)
#define perf_pmasys_gpc_trigger_start_mask_r()                     (0x0024a65cU)
#define perf_pmasys_gpc_trigger_start_maskb_r()                    (0x0024a660U)
#define perf_pmasys_gpc_trigger_stop_mask_r()                      (0x0024a674U)
#define perf_pmasys_gpc_trigger_stop_maskb_r()                     (0x0024a678U)
#define perf_pmasys_gpc_trigger_config_tesla_mode_r()              (0x0024a6a0U)
#define perf_pmasys_gpc_trigger_config_tesla_modeb_r()             (0x0024a6a4U)
#define perf_pmasys_gpc_trigger_config_mixed_mode_r()              (0x0024a6b8U)
#define perf_pmasys_gpc_trigger_config_mixed_modeb_r()             (0x0024a6bcU)
#define perf_pmasys_gpc_trigger_start_r()                          (0x0024a6d0U)
#define perf_pmasys_gpc_trigger_startb_r()                         (0x0024a6d4U)
#define perf_pmasys_gpc_trigger_status_r()                         (0x0024a700U)
#define perf_pmasys_gpc_trigger_statusb_r()                        (0x0024a704U)
#define perf_pmasys_fbp_trigger_start_mask_r()                     (0x0024a664U)
#define perf_pmasys_fbp_trigger_start_maskb_r()                    (0x0024a668U)
#define perf_pmasys_fbp_trigger_stop_mask_r()                      (0x0024a67cU)
#define perf_pmasys_fbp_trigger_stop_maskb_r()                     (0x0024a680U)
#define perf_pmasys_fbp_trigger_config_tesla_mode_r()              (0x0024a6a8U)
#define perf_pmasys_fbp_trigger_config_tesla_modeb_r()             (0x0024a6acU)
#define perf_pmasys_fbp_trigger_config_mixed_mode_r()              (0x0024a6c0U)
#define perf_pmasys_fbp_trigger_config_mixed_modeb_r()             (0x0024a6c4U)
#define perf_pmasys_fbp_trigger_start_r()                          (0x0024a6d8U)
#define perf_pmasys_fbp_trigger_startb_r()                         (0x0024a6dcU)
#define perf_pmasys_fbp_trigger_status_r()                         (0x0024a708U)
#define perf_pmasys_fbp_trigger_statusb_r()                        (0x0024a70cU)
#endif
