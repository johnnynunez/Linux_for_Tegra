// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2016-2023, NVIDIA CORPORATION.  All rights reserved.
 */

#ifndef __IMX274_H__
#define __IMX274_H__

#include <uapi/media/imx274.h>

#define IMX274_SVR_ADDR				0x300E

#define IMX274_SHR_ADDR_LSB			0x300C
#define IMX274_SHR_ADDR_MSB			0x300D

#define IMX274_SHR_DOL1_ADDR_LSB		0x302E
#define IMX274_SHR_DOL1_ADDR_MSB		0x302F
#define IMX274_SHR_DOL2_ADDR_LSB		0x3030
#define IMX274_SHR_DOL2_ADDR_MSB		0x3031
#define IMX274_RHS1_ADDR_LSB			0x3032
#define IMX274_RHS1_ADDR_MSB			0x3033

#define IMX274_VMAX_ADDR_LSB			0x30F8
#define IMX274_VMAX_ADDR_MID			0x30F9
#define IMX274_VMAX_ADDR_MSB			0x30FA

#define IMX274_ANALOG_GAIN_ADDR_LSB		0x300A
#define IMX274_ANALOG_GAIN_ADDR_MSB		0x300B
#define IMX274_DIGITAL_GAIN_ADDR		0x3012

#define IMX274_GROUP_HOLD_ADDR			0x302D

struct imx274_power_rail {
	struct regulator *dvdd;
	struct regulator *avdd;
	struct regulator *iovdd;
	struct regulator *ext_reg1;
	struct regulator *ext_reg2;
	struct clk *mclk;
	unsigned int pwdn_gpio;
	unsigned int cam1_gpio;
	unsigned int reset_gpio;
	unsigned int af_gpio;
};

struct imx274_platform_data {
	const char *mclk_name; /* NULL for default default_mclk */
	unsigned int cam1_gpio;
	unsigned int reset_gpio;
	unsigned int af_gpio;
	bool ext_reg;
	int (*power_on)(struct imx274_power_rail *pw);
	int (*power_off)(struct imx274_power_rail *pw);
};

#endif  /* __IMX274_H__ */
