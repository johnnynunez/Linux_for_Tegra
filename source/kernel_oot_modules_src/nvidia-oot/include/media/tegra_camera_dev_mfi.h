/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2015-2022, NVIDIA CORPORATION.  All rights reserved.
 */

#ifndef __CAMERA_DEV_MFI_H__
#define __CAMERA_DEV_MFI_H__

#include <linux/list.h>
#include <linux/i2c.h>
#include <linux/regmap.h>

#define CAMERA_MAX_NAME_LENGTH	32
#define CAMERA_REGCACHE_MAX		(128)

struct cam_reg {
	u32 addr;
	u32 val;
};

struct cam_i2c_msg {
	struct i2c_msg msg;
	u8 buf[8];
};

struct camera_mfi_dev {
	char name[CAMERA_MAX_NAME_LENGTH];
	struct regmap *regmap;
	struct cam_reg reg[CAMERA_REGCACHE_MAX];
	struct cam_reg prev_reg[CAMERA_REGCACHE_MAX];
	struct i2c_client *i2c_client;
	struct cam_i2c_msg msg[CAMERA_REGCACHE_MAX];
	u32 num_used;
	u32 prev_num_used;
	struct list_head list;
};

struct mfi_cb_arg {
	u8 vi_chan;
};

void tegra_camera_dev_mfi_cb(void *stub);
int tegra_camera_dev_mfi_clear(struct camera_mfi_dev *cmfidev);
int tegra_camera_dev_mfi_wr_add(
	struct camera_mfi_dev *cmfidev, u32 offset, u32 val);
int tegra_camera_dev_mfi_wr_add_i2c(
	struct camera_mfi_dev *cmfidev, struct i2c_msg *msg, int num);
int tegra_camera_dev_mfi_add_regmap(
	struct camera_mfi_dev **cmfidev, u8 *name, struct regmap *regmap);
int tegra_camera_dev_mfi_add_i2cclient(
	struct camera_mfi_dev **cmfidev, u8 *name,
	struct i2c_client *i2c_client);

#endif
/* __CAMERA_DEV_MFI_H__ */
