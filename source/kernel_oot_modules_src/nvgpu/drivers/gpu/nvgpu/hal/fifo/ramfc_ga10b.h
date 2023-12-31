/*
 * Copyright (c) 2020-2023, NVIDIA CORPORATION.  All rights reserved.
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

#ifndef NVGPU_RAMFC_GA10B_H
#define NVGPU_RAMFC_GA10B_H

#include <nvgpu/types.h>

struct nvgpu_channel;
struct nvgpu_channel_dump_info;

int ga10b_ramfc_setup(struct nvgpu_channel *ch, u64 gpfifo_base,
		u32 gpfifo_entries, u64 pbdma_acquire_timeout, u32 flags);
void ga10b_ramfc_capture_ram_dump_1(struct gk20a *g,
		struct nvgpu_channel *ch, struct nvgpu_channel_dump_info *info);
void ga10b_ramfc_capture_ram_dump_2(struct gk20a *g,
		struct nvgpu_channel *ch, struct nvgpu_channel_dump_info *info);
void ga10b_ramfc_capture_ram_dump(struct gk20a *g, struct nvgpu_channel *ch,
				  struct nvgpu_channel_dump_info *info);
#endif /* NVGPU_RAMFC_GA10B_H */
