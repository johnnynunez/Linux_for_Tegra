/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef _TEGRA_VBLK_H_
#define _TEGRA_VBLK_H_

#include <linux/blkdev.h>
#include <linux/bio.h>
#include <soc/tegra/ivc-priv.h>
#include <soc/tegra/ivc_ext.h>
#include <soc/tegra/virt/hv-ivc.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <tegra_virt_storage_spec.h>

#define OOPS_DRV_NAME "tegra_hv_vblk_oops"

#define IVC_RESET_RETRIES	30
#define VSC_RESPONSE_RETRIES	10

/* one IVC for regular IO and one for panic write */
#define VSC_REQ_RW 0
#define VSC_REQ_PANIC (VSC_REQ_RW+1)
#define MAX_OOPS_VSC_REQS (VSC_REQ_PANIC+1)

/* wait time for response from VSC */
#define VSC_RESPONSE_WAIT_MS 1

/* PSTORE defaults */
#define PSTORE_KMSG_RECORD_SIZE (64*1024)


struct vsc_request {
	struct vs_request vs_req;
	struct request *req;
	struct vblk_ioctl_req *ioctl_req;
	void *mempool_virt;
	uint32_t mempool_offset;
	uint32_t mempool_len;
	uint32_t id;
	struct vblk_dev *vblkdev;
	/* Scatter list for maping IOVA address */
	struct scatterlist *sg_lst;
	int sg_num_ents;
};

/*
 * The drvdata of virtual device.
 */
struct vblk_dev {
	struct vs_config_info config;
	uint64_t size;                   /* Device size in bytes */
	uint32_t ivc_id;
	uint32_t ivm_id;
	struct tegra_hv_ivc_cookie *ivck;
	struct tegra_hv_ivm_cookie *ivmk;
	uint32_t devnum;
	bool initialized;
	struct delayed_work init;
	struct device *device;
	void *shared_buffer;
	struct vsc_request reqs[MAX_OOPS_VSC_REQS];
	DECLARE_BITMAP(pending_reqs, MAX_OOPS_VSC_REQS);
	uint32_t inflight_reqs;
	uint32_t max_requests;
	struct mutex ivc_lock;
	int pstore_max_reason;		/* pstore max_reason */
	uint32_t pstore_kmsg_size;	/* pstore kmsg record size */
};

#endif
