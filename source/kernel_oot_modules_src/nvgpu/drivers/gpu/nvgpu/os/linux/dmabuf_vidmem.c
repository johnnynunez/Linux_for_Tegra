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

#include <linux/version.h>
#include <linux/scatterlist.h>
#include <linux/dma-direction.h>
#include <linux/dma-buf.h>
#include <uapi/linux/nvgpu.h>

#ifdef CONFIG_NVGPU_IGNORE_PROCESS_FD_LIMIT
#include <linux/fdtable.h>
#include <linux/fs.h>
#endif

#include <nvgpu/dma.h>
#include <nvgpu/enabled.h>
#include <nvgpu/vidmem.h>
#include <nvgpu/nvgpu_mem.h>
#include <nvgpu/page_allocator.h>
#include <nvgpu/gk20a.h>
#include <nvgpu/nvgpu_init.h>

#include <nvgpu/linux/vm.h>
#include <nvgpu/linux/dma.h>

#include "dmabuf_vidmem.h"

bool nvgpu_addr_is_vidmem_page_alloc(u64 addr)
{
	return !!(addr & 1ULL);
}

/* This constant string is used to determine if the dmabuf belongs
 * to nvgpu.
 */
static const char exporter_name[] = "nvgpu";

void nvgpu_vidmem_set_page_alloc(struct scatterlist *sgl, u64 addr)
{
	/* set bit 0 to indicate vidmem allocation */
	sg_dma_address(sgl) = (addr | 1ULL);
}

struct nvgpu_page_alloc *nvgpu_vidmem_get_page_alloc(struct scatterlist *sgl)
{
	u64 addr;

	addr = sg_dma_address(sgl);

	if (nvgpu_addr_is_vidmem_page_alloc(addr))
		addr = addr & ~1ULL;
	else
		WARN_ON(1);

	return (struct nvgpu_page_alloc *)(uintptr_t)addr;
}

static struct sg_table *gk20a_vidbuf_map_dma_buf(
	struct dma_buf_attachment *attach, enum dma_data_direction dir)
{
	struct nvgpu_vidmem_buf *buf = attach->dmabuf->priv;

	return buf->mem->priv.sgt;
}

static void gk20a_vidbuf_unmap_dma_buf(struct dma_buf_attachment *attach,
				       struct sg_table *sgt,
				       enum dma_data_direction dir)
{
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
static void *gk20a_vidbuf_kmap(struct dma_buf *dmabuf, unsigned long page_num)
{
	WARN_ON("Not supported");
	return NULL;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 16, 0)
static void *gk20a_vidbuf_kmap_atomic(struct dma_buf *dmabuf,
				      unsigned long page_num)
{
	WARN_ON("Not supported");
	return NULL;
}
#endif

static int gk20a_vidbuf_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static void gk20a_vidbuf_release(struct dma_buf *dmabuf)
{
	struct nvgpu_vidmem_buf *buf = dmabuf->priv;
	struct nvgpu_vidmem_linux *linux_buf = buf->priv;
	struct gk20a *g = buf->g;

	vidmem_dbg(g, "Releasing Linux VIDMEM buf: dmabuf=0x%p size=%zuKB",
		   dmabuf, buf->mem->size >> 10);

	nvgpu_kfree(g, linux_buf);
	nvgpu_vidmem_buf_free(g, buf);

	nvgpu_put(g);
}

static struct dma_buf_ops gk20a_vidbuf_ops = {
	.map_dma_buf      = gk20a_vidbuf_map_dma_buf,
	.unmap_dma_buf    = gk20a_vidbuf_unmap_dma_buf,
	.release          = gk20a_vidbuf_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 16, 0)
	.map_atomic      = gk20a_vidbuf_kmap_atomic,
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
	.map             = gk20a_vidbuf_kmap,
#endif
#else
	.kmap_atomic      = gk20a_vidbuf_kmap_atomic,
	.kmap             = gk20a_vidbuf_kmap,
#endif
	.mmap             = gk20a_vidbuf_mmap,
};

static struct dma_buf *gk20a_vidbuf_export(struct nvgpu_vidmem_buf *buf)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	exp_info.priv = buf;
	exp_info.ops = &gk20a_vidbuf_ops;
	exp_info.size = buf->mem->size;
	exp_info.flags = O_RDWR;
	exp_info.exp_name = exporter_name;

	return dma_buf_export(&exp_info);
}

struct gk20a *nvgpu_vidmem_buf_owner(struct dma_buf *dmabuf)
{
	struct nvgpu_vidmem_buf *buf = dmabuf->priv;

	if (dmabuf->exp_name != exporter_name) {
		return NULL;
	}

	return buf->g;
}

int nvgpu_vidmem_export_linux(struct gk20a *g, size_t bytes)
{
	struct nvgpu_vidmem_buf *buf = NULL;
	struct nvgpu_vidmem_linux *priv;
	int err, fd;

	/*
	 * This ref is released when the dma_buf is closed.
	 */
	if (!nvgpu_get(g))
		return -ENODEV;

	vidmem_dbg(g, "Allocating vidmem buf: %zu bytes", bytes);

	priv = nvgpu_kzalloc(g, sizeof(*priv));
	if (!priv) {
		err = -ENOMEM;
		goto fail;
	}

	err = nvgpu_vidmem_user_alloc(g, bytes, &buf);
	if (0 != err) {
		goto fail;
	}

	priv->dmabuf = gk20a_vidbuf_export(buf);
	if (IS_ERR(priv->dmabuf)) {
		err = PTR_ERR(priv->dmabuf);
		goto fail;
	}

	buf->priv = priv;

#ifdef CONFIG_NVGPU_IGNORE_PROCESS_FD_LIMIT
	fd = __alloc_fd(current->files, 1024, sysctl_nr_open,
			O_RDWR | O_CLOEXEC);
#else
	fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
#endif
	if (fd < 0) {
		/* ->release frees what we have done */
		dma_buf_put(priv->dmabuf);
		return fd;
	}

	/* fclose() on this drops one ref, freeing the dma buf */
	fd_install(fd, priv->dmabuf->file);

	vidmem_dbg(g, "Alloced Linux VIDMEM buf: dmabuf=0x%p size=%zuKB",
		   priv->dmabuf, buf->mem->size >> 10);

	return fd;

fail:
	nvgpu_vidmem_buf_free(g, buf);
	nvgpu_kfree(g, priv);
	nvgpu_put(g);

	vidmem_dbg(g, "Failed to alloc Linux VIDMEM buf: %d", err);
	return err;
}

int nvgpu_vidmem_buf_access_memory(struct gk20a *g, struct dma_buf *dmabuf,
		void *buffer, u64 offset, u64 size, u32 cmd)
{
	struct nvgpu_vidmem_buf *vidmem_buf;
	struct nvgpu_mem *mem;
	int err = 0;

	if (gk20a_dmabuf_aperture(g, dmabuf) != APERTURE_VIDMEM)
		return -EINVAL;

	vidmem_buf = dmabuf->priv;
	mem = vidmem_buf->mem;

	nvgpu_speculation_barrier();
	switch (cmd) {
	case NVGPU_DBG_GPU_IOCTL_ACCESS_FB_MEMORY_CMD_READ:
		nvgpu_mem_rd_n(g, mem, offset, buffer, size);
		break;

	case NVGPU_DBG_GPU_IOCTL_ACCESS_FB_MEMORY_CMD_WRITE:
		nvgpu_mem_wr_n(g, mem, offset, buffer, size);
		break;

	default:
		err = -EINVAL;
	}

	return err;
}

void nvgpu_mem_free_vidmem_alloc(struct gk20a *g, struct nvgpu_mem *vidmem)
{
	nvgpu_free(vidmem->allocator,
		   (u64)nvgpu_vidmem_get_page_alloc(vidmem->priv.sgt->sgl));
	nvgpu_free_sgtable(g, &vidmem->priv.sgt);
}
