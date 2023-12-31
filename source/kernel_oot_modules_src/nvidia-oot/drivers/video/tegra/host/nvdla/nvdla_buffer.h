/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019-2023, NVIDIA Corporation.  All rights reserved.
 *
 * NVDLA Buffer Management Header
 */

#ifndef __NVHOST_NVDLA_BUFFER_H__
#define __NVHOST_NVDLA_BUFFER_H__

#include <linux/dma-buf.h>
#include <uapi/linux/nvhost_nvdla_ioctl.h>

enum nvdla_buffers_heap {
	NVDLA_BUFFERS_HEAP_DRAM = 0,
};

/**
 * @brief		Information needed for buffers
 *
 * pdev			Pointer to NVHOST device
 * rb_root		RB tree root for of all the buffers used by a file pointer
 * list			List for traversing through all the buffers
 * mutex		Mutex for the buffer tree and the buffer list
 * kref			Reference count for the bufferlist
 *
 */
struct nvdla_buffers {
	struct platform_device *pdev;

	struct list_head list_head;
	struct rb_root rb_root;
	struct mutex mutex;

	struct kref kref;
};

/**
 * @brief			Initialize the nvdla_buffer per open request
 *
 * This function allocates nvdla_buffers struct and init the bufferlist
 * and mutex.
 *
 * @param nvdla_buffers	Pointer to nvdla_buffers struct
 * @return			nvdla_buffers pointer on success
 *					or negative on error
 *
 */
struct nvdla_buffers *nvdla_buffer_init(struct platform_device *pdev);

/**
 * @brief	Checks for validity of nvdla_buffer
 *
 * This function checks the validity of buffer and is
 * recommended to be called prior to any buffer operations
 *
 * @param nvdla_buffers Pointer to nvdla_buffers struct
 * @return	            true on buffer being valid, and false otherwise
 **/
bool nvdla_buffer_is_valid(struct nvdla_buffers *nvdla_buffers);

/**
 * @brief	Sets host1x platform device corresponding to nvdla_buffer
 *
 * This function resets the platform_device pdev information of nvdla_buffer.
 *
 * @param nvdla_buffers	Pointer to nvdla_buffers struct
 * @param pdev			Pointer to NvHost device
 **/
void nvdla_buffer_set_platform_device(struct nvdla_buffers *nvdla_buffers,
		struct platform_device *pdev);

/**
 * @brief			Pin the memhandle using dma_buf functions
 *
 * This function maps the buffer memhandle list passed from user side
 * to device iova.
 *
 * @param nvdla_buffers		Pointer to nvdla_buffers struct
 * @param descs			Descs Pointer to share descriptor list
 * @param count			Number of memhandles in the list
 * @return			0 on success or negative on error
 *
 */
int nvdla_buffer_pin(struct nvdla_buffers *nvdla_buffers,
			struct nvdla_mem_share_handle *descs,
			u32 count);

/**
 * @brief			UnPins the mapped address space.
 *
 * @param nvdla_buffers		Pointer to nvdla_buffer struct
 * @param descs			Descs Pointer to share descriptor list
 * @param count			Number of memhandles in the list
 * @return			None
 *
 */
void nvdla_buffer_unpin(struct nvdla_buffers *nvdla_buffers,
				struct nvdla_mem_share_handle *descs,
				u32 count);

/**
 * @brief			Pin the mapped buffer for a task submit
 *
 * This function increased the reference count for a mapped buffer during
 * task submission.
 *
 * @param nvdla_buffers		Pointer to nvdla_buffer struct
 * @param handles		Pointer to MemHandle list
 * @param count			Number of memhandles in the list
 * @param paddr			Pointer to IOVA list
 * @param psize			Pointer to size of buffer to return
 * @param heap			Pointer to a list of heaps. This is
 *				filled by the routine.
 *
 * @return			0 on success or negative on error
 *
 */
int nvdla_buffer_submit_pin(struct nvdla_buffers *nvdla_buffers,
			     u32 *handles, u32 count,
			     dma_addr_t *paddr, size_t *psize,
			     enum nvdla_buffers_heap *heap);

/**
 * @brief		UnPins the mapped address space on task completion.
 *
 * This function decrease the reference count for a mapped buffer when the
 * task get completed or aborted.
 *
 * @param nvdla_buffers		Pointer to nvdla_buffer struct
 * @param handles		Pointer to MemHandle list
 * @param count			Number of memhandles in the list
 * @return			None
 *
 */
void nvdla_buffer_submit_unpin(struct nvdla_buffers *nvdla_buffers,
					u32 *handles, u32 count);

/**
 * @brief			Drop a user reference to buffer structure
 *
 * @param nvdla_buffers	Pointer to nvdla_buffer struct
 * @return			None
 *
 */
void nvdla_buffer_release(struct nvdla_buffers *nvdla_buffers);

#endif /*__NVHOST_NVDLA_BUFFER_H__ */
