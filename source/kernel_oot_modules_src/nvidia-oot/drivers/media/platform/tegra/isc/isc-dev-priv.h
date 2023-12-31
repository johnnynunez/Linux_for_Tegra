/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2015-2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef __ISC_DEV_PRIV_H__
#define __ISC_DEV_PRIV_H__

#include <linux/cdev.h>

struct isc_dev_info {
	struct i2c_client *i2c_client;
	struct device *dev;
	struct cdev cdev;
	struct isc_dev_platform_data *pdata;
	atomic_t in_use;
	struct mutex mutex;
	struct isc_dev_package rw_pkg;
	struct dentry *d_entry;
	u32 reg_len;
	u32 reg_off;
	char devname[32];
	u8 power_is_on;
};

int isc_dev_raw_rd(struct isc_dev_info *, unsigned int,
	unsigned int, u8 *, size_t);
int isc_dev_raw_wr(struct isc_dev_info *, unsigned int, u8 *, size_t);

int isc_dev_debugfs_init(struct isc_dev_info *isc_dev);
int isc_dev_debugfs_remove(struct isc_dev_info *isc_dev);

#endif  /* __ISC_DEV_PRIV_H__ */
