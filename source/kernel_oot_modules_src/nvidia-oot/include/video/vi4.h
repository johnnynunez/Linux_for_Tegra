/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Tegra Graphics Host VI
 *
 * Copyright (c) 2015-2022, NVIDIA Corporation.  All rights reserved.
 */

#ifndef __TEGRA_VI4_H__
#define __TEGRA_VI4_H__

#include <media/mc_common.h>

struct reset_control;

extern struct vi_notify_driver nvhost_vi_notify_driver;
void nvhost_vi_notify_error(struct platform_device *);

struct nvhost_vi_dev {
	struct nvhost_vi_notify_dev *hvnd;
	struct reset_control *vi_reset;
	struct reset_control *vi_tsc_reset;
	struct dentry *debug_dir;
	int error_irq;
	bool busy;
	atomic_t overflow;
	atomic_t notify_overflow;
	atomic_t fmlite_overflow;
	struct tegra_mc_vi mc_vi;
	unsigned int vi_bypass_bw;
};

int nvhost_vi4_prepare_poweroff(struct platform_device *);
int nvhost_vi4_finalize_poweron(struct platform_device *);
void nvhost_vi4_idle(struct platform_device *);
void nvhost_vi4_busy(struct platform_device *);
void nvhost_vi4_reset(struct platform_device *);
int nvhost_vi4_aggregate_constraints(struct platform_device *dev,
				int clk_index,
				unsigned long floor_rate,
				unsigned long pixelrate,
				unsigned long bw_constraint);

int vi4_v4l2_set_la(struct platform_device *pdev,
			u32 vi_bypass_bw, u32 is_ioctl);
#endif
