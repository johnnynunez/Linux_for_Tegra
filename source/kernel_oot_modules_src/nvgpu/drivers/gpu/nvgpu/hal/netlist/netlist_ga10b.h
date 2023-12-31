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
#ifndef NVGPU_NETLIST_GA10B_H
#define NVGPU_NETLIST_GA10B_H

#include <nvgpu/types.h>
#include <nvgpu/netlist_defs.h>

struct gk20a;

/* NVGPU_NETLIST_IMAGE_C is FNL for ga10b */
#define GA10B_NETLIST_IMAGE_FW_NAME NVGPU_NETLIST_IMAGE_C

#define NVGPU_NETLIST_DBG_IMAGE_A	"NETA_img_debug_encrypted.bin"
#define NVGPU_NETLIST_DBG_IMAGE_B	"NETB_img_debug_encrypted.bin"
#define NVGPU_NETLIST_DBG_IMAGE_C	"NETC_img_debug_encrypted.bin"
#define NVGPU_NETLIST_DBG_IMAGE_D	"NETD_img_debug_encrypted.bin"

#define NVGPU_NETLIST_PROD_IMAGE_A	"NETA_img_prod_encrypted.bin"
#define NVGPU_NETLIST_PROD_IMAGE_B	"NETB_img_prod_encrypted.bin"
#define NVGPU_NETLIST_PROD_IMAGE_C	"NETC_img_prod_encrypted.bin"
#define NVGPU_NETLIST_PROD_IMAGE_D	"NETD_img_prod_encrypted.bin"

/* NVGPU_NETLIST_IMAGE_C is FNL for ga10b */
#define GA10B_NETLIST_DBG_IMAGE_FW_NAME NVGPU_NETLIST_DBG_IMAGE_C
#define GA10B_NETLIST_PROD_IMAGE_FW_NAME NVGPU_NETLIST_PROD_IMAGE_C

int ga10b_netlist_get_name(struct gk20a *g, int index, char *name);
bool ga10b_netlist_is_firmware_defined(void);

#endif /* NVGPU_NETLIST_GA10B_H */
