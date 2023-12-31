/*
 * Copyright (c) 2016-2022, NVIDIA CORPORATION.  All rights reserved.
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

#ifndef NVGPU_RAMIN_GV11B_H
#define NVGPU_RAMIN_GV11B_H

#include <nvgpu/types.h>

struct gk20a;
struct nvgpu_mem;

void gv11b_ramin_set_gr_ptr(struct gk20a *g,
		struct nvgpu_mem *inst_block, u64 gpu_va);
void gv11b_ramin_set_subctx_pdb_info(struct gk20a *g,
		u32 subctx_id, struct nvgpu_mem *pdb_mem,
		bool replayable, bool add, u32 *subctx_pdb_map);
void gv11b_ramin_init_subctx_pdb_map(struct gk20a *g,
		u32 *subctx_pdb_map);
void gv11b_ramin_init_subctx_valid_mask(struct gk20a *g,
		struct nvgpu_mem *inst_block, unsigned long *valid_subctx_mask);
void gv11b_ramin_init_subctx_pdb(struct gk20a *g,
		struct nvgpu_mem *inst_block, u32 *subctx_pdb_map);
void gv11b_ramin_set_eng_method_buffer(struct gk20a *g,
		struct nvgpu_mem *inst_block, u64 gpu_va);
void gv11b_ramin_init_pdb(struct gk20a *g, struct nvgpu_mem *inst_block,
		u64 pdb_addr, struct nvgpu_mem *pdb_mem);

#endif /* NVGPU_RAMIN_GV11B_H */
