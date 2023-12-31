/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2016-2023, NVIDIA CORPORATION. All rights reserved.
 *
 * Function naming determines intended use:
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
#ifndef _hw_sec_pva_v1_h_
#define _hw_sec_pva_v1_h_

static inline u32 v1_sec_lic_intr_enable_r(void)
{
	return 0x2804CU;
}
static inline u32 sec_lic_intr_enable_dma0_f(u32 v)
{
	return (v & 0x1) << 9;
}
static inline u32 sec_lic_intr_enable_dma1_f(u32 v)
{
	return (v & 0x1) << 8;
}
static inline u32 sec_lic_intr_enable_actmon_f(u32 v)
{
	return (v & 0x1) << 7;
}
static inline u32 sec_lic_intr_enable_h1x_f(u32 v)
{
	return (v & 0x7) << 5;
}
static inline u32 sec_lic_intr_enable_hsp_f(u32 v)
{
	return (v & 0xf) << 1;
}
static inline u32 sec_lic_intr_enable_wdt_f(u32 v)
{
	return (v & 0x1) << 0;
}
static inline u32 v1_sec_lic_intr_status_r(void)
{
	return 0x28054U;
}
#endif
