/*
 * Copyright (c) 2017-2022, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __NVGPU_LINUX_DMA_H__
#define __NVGPU_LINUX_DMA_H__

/**
 * Functions used internally for building the backing SGTs for nvgpu_mems.
 */


int nvgpu_get_sgtable_attrs(struct gk20a *g, struct sg_table **sgt,
		      void *cpuva, u64 iova,
		      size_t size, unsigned long flags);

int nvgpu_get_sgtable(struct gk20a *g, struct sg_table **sgt,
		      void *cpuva, u64 iova, size_t size);

int nvgpu_get_sgtable_from_pages(struct gk20a *g, struct sg_table **sgt,
				 struct page **pages, u64 iova,
				 size_t size);

void nvgpu_free_sgtable(struct gk20a *g, struct sg_table **sgt);

/**
 * nvgpu_dma_mmap_sys - Map allocated memory into userspace
 *
 * @param g     - The GPU.
 * @param vma   - User provided VMA
 * @param mem   - Struct for retrieving the information about the allocated buffer. Must be
 *                allocated via a call to nvgpu_dma_alloc* API and use SYSMEM aperture.
 *                Following flags modifying the operation of the DMA mapping.
 *                are accepted:
 *                - %NVGPU_DMA_NO_KERNEL_MAPPING
 *                - %NVGPU_DMA_PHYSICALLY_ADDRESSED
 *
 * Map memory suitable for doing DMA into a valid user VMA.
 * Returns 0 on success and a suitable error code when there's an error. This requires
 * that a buffer(mem) is already allocated using nvgpu_dma_alloc* API.
 *
 * @return	0 For success, < 0 for failure.
 * @retval	-EINVAL incorrect parameters
 * @retval	-EEXIST VMA is already mapped.
 * @retval	Other failures.
 */
int nvgpu_dma_mmap_sys(struct gk20a *g, struct vm_area_struct *vma, struct nvgpu_mem *mem);

#endif
