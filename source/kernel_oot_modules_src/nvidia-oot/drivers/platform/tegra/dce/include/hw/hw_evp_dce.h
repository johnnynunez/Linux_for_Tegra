/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019-2023, NVIDIA CORPORATION.  All rights reserved.
 */
/*
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
#ifndef HW_EVP_DCE_H
#define HW_EVP_DCE_H

static inline u32 evp_reset_addr_r(void)
{
	return 0x20U;
}
static inline u32 evp_undef_addr_r(void)
{
	return 0x4U;
}
static inline u32 evp_swi_addr_r(void)
{
	return 0x28U;
}
static inline u32 evp_prefetch_abort_addr_r(void)
{
	return 0x2cU;
}
static inline u32 evp_data_abort_addr_r(void)
{
	return 0x30U;
}
static inline u32 evp_rsvd_addr_r(void)
{
	return 0x34U;
}
static inline u32 evp_irq_addr_r(void)
{
	return 0x38U;
}
static inline u32 evp_fiq_addr_r(void)
{
	return 0x3cU;
}
#endif
