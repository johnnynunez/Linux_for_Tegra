// SPDX-License-Identifier: GPL-2.0
/*
 * imx274_mode_tbls.h - imx274 sensor driver
 *
 * Copyright (c) 2016-2023, NVIDIA CORPORATION.  All rights reserved.
 */

#ifndef __IMX274_I2C_TABLES__
#define __IMX274_I2C_TABLES__

#include <media/camera_common.h>

#define IMX274_TABLE_WAIT_MS 0
#define IMX274_TABLE_END 1
#define IMX274_WAIT_MS 1
#define IMX274_WAIT_MS_START	15

#define ENABLE_EXTRA_MODES 0

#define imx274_reg struct reg_8

static const imx274_reg imx274_start[] = {
	{0x3000, 0x00}, /* mode select streaming on */
	{0x303E, 0x02},
	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS_START},
	{0x30F4, 0x00},
	{0x3018, 0xA2},
	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS_START},
	{IMX274_TABLE_END, 0x00}
};

static const imx274_reg imx274_stop[] = {
	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{0x3000, 0x01}, /* mode select streaming off */
	{IMX274_TABLE_END, 0x00}
};

static const imx274_reg tp_colorbars[] = {
	/* test pattern */
	{0x303C, 0x11},
	{0x303D, 0x0B},
	{0x370B, 0x11},
	{0x370E, 0x00},
	{0x377F, 0x01},
	{0x3781, 0x01},
	{IMX274_TABLE_END, 0x00}
};


/* Mode 1 : 3840X2160 10 bits 30fps*/
static const imx274_reg mode_3840X2160[] = {
	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{0x3000, 0x12}, /* mode select streaming on */
	/* input freq. 24M */
	{0x3120, 0xF0},
	{0x3122, 0x02},
	{0x3129, 0x9c},
	{0x312A, 0x02},
	{0x312D, 0x02},

	{0x310B, 0x00},
	{0x304C, 0x00},
	{0x304D, 0x03},
	{0x331C, 0x1A},
	{0x3502, 0x02},
	{0x3529, 0x0E},
	{0x352A, 0x0E},
	{0x352B, 0x0E},
	{0x3538, 0x0E},
	{0x3539, 0x0E},
	{0x3553, 0x00},
	{0x357D, 0x05},
	{0x357F, 0x05},
	{0x3581, 0x04},
	{0x3583, 0x76},
	{0x3587, 0x01},
	{0x35BB, 0x0E},
	{0x35BC, 0x0E},
	{0x35BD, 0x0E},
	{0x35BE, 0x0E},
	{0x35BF, 0x0E},
	{0x366E, 0x00},
	{0x366F, 0x00},
	{0x3670, 0x00},
	{0x3671, 0x00},
	{0x30EE, 0x01},
	{0x3304, 0x32},
	{0x3306, 0x32},
	{0x3590, 0x32},
	{0x3686, 0x32},
	/* resolution */
	{0x30E2, 0x01},
	{0x30F6, 0x07},
	{0x30F7, 0x01},
	{0x30F8, 0xC6},
	{0x30F9, 0x11},
	{0x3130, 0x78}, /*WRITE_VSIZE*/
	{0x3131, 0x08},
	{0x3132, 0x70}, /*Y_OUT_SIZE*/
	{0x3133, 0x08},

	/* crop */
	{0x30DD, 0x01}, /*VWIDCUTEN*/
	{0x30DE, 0x04}, /*VWIDCUT*/
	{0x30E0, 0x03}, /*VWINCUTPOS*/
	{0x3037, 0x01}, /*HTRIMMING_EN*/
	{0x3038, 0x0C}, /*HTRIMMING_START*/
	{0x3039, 0x00},
	{0x303A, 0x0C}, /*HTRIMMING_END*/
	{0x303B, 0x0F},

	/* mode setting */
	{0x3004, 0x01},
	{0x3005, 0x01},
	{0x3006, 0x00},
	{0x3007, 0xA2},
	{0x300C, 0x0C}, /* SHR: Minimum 12 */
	{0x300D, 0x00},
	{0x300E, 0x01},
	{0x3019, 0x00},
	{0x3A41, 0x08},
	{0x3342, 0x0A},
	{0x3343, 0x00},
	{0x3344, 0x16},
	{0x3345, 0x00},
	{0x3528, 0x0E},
	{0x3554, 0x1F},
	{0x3555, 0x01},
	{0x3556, 0x01},
	{0x3557, 0x01},
	{0x3558, 0x01},
	{0x3559, 0x00},
	{0x355A, 0x00},
	{0x35BA, 0x0E},
	{0x366A, 0x1B},
	{0x366B, 0x1A},
	{0x366C, 0x19},
	{0x366D, 0x17},
	{0x33A6, 0x01},
	{0x306B, 0x05},

	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{IMX274_TABLE_END, 0x0000}
};

/* Mode 1 : 3840X2160 10 bits 60fps*/
static const imx274_reg mode_3840X2160_60fps[] = {
	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{0x3000, 0x12}, /* mode select streaming on */
	/* input freq. 24M */
	{0x3120, 0xF0},
	{0x3122, 0x02},
	{0x3129, 0x9c},
	{0x312A, 0x02},
	{0x312D, 0x02},

	{0x310B, 0x00},
	{0x304C, 0x00},
	{0x304D, 0x03},
	{0x331C, 0x1A},
	{0x3502, 0x02},
	{0x3529, 0x0E},
	{0x352A, 0x0E},
	{0x352B, 0x0E},
	{0x3538, 0x0E},
	{0x3539, 0x0E},
	{0x3553, 0x00},
	{0x357D, 0x05},
	{0x357F, 0x05},
	{0x3581, 0x04},
	{0x3583, 0x76},
	{0x3587, 0x01},
	{0x35BB, 0x0E},
	{0x35BC, 0x0E},
	{0x35BD, 0x0E},
	{0x35BE, 0x0E},
	{0x35BF, 0x0E},
	{0x366E, 0x00},
	{0x366F, 0x00},
	{0x3670, 0x00},
	{0x3671, 0x00},
	{0x30EE, 0x01},
	{0x3304, 0x32},
	{0x3306, 0x32},
	{0x3590, 0x32},
	{0x3686, 0x32},
	/* resolution */
	{0x30E2, 0x01},
	{0x30F6, 0x07},
	{0x30F7, 0x01},
	{0x30F8, 0xC6},
	{0x30F9, 0x11},
	{0x3130, 0x78}, /*WRITE_VSIZE*/
	{0x3131, 0x08},
	{0x3132, 0x70}, /*Y_OUT_SIZE*/
	{0x3133, 0x08},

	/* crop */
	{0x30DD, 0x01}, /*VWIDCUTEN*/
	{0x30DE, 0x04}, /*VWIDCUT*/
	{0x30E0, 0x03}, /*VWINCUTPOS*/
	{0x3037, 0x01}, /*HTRIMMING_EN*/
	{0x3038, 0x0C}, /*HTRIMMING_START*/
	{0x3039, 0x00},
	{0x303A, 0x0C}, /*HTRIMMING_END*/
	{0x303B, 0x0F},

	/* mode setting */
	{0x3004, 0x01},
	{0x3005, 0x01},
	{0x3006, 0x00},
	{0x3007, 0x02},
	{0x300C, 0x0C}, /* SHR: Minimum 12 */
	{0x300D, 0x00},
	{0x300E, 0x00},
	{0x3019, 0x00},
	{0x3A41, 0x08},
	{0x3342, 0x0A},
	{0x3343, 0x00},
	{0x3344, 0x16},
	{0x3345, 0x00},
	{0x3528, 0x0E},
	{0x3554, 0x1F},
	{0x3555, 0x01},
	{0x3556, 0x01},
	{0x3557, 0x01},
	{0x3558, 0x01},
	{0x3559, 0x00},
	{0x355A, 0x00},
	{0x35BA, 0x0E},
	{0x366A, 0x1B},
	{0x366B, 0x1A},
	{0x366C, 0x19},
	{0x366D, 0x17},
	{0x33A6, 0x01},
	{0x306B, 0x05},

	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{IMX274_TABLE_END, 0x0000}
};

/* Mode1(DOL): 3840x2160 10 bits 30fps DOL-HDR
 * Active H: LI (4) + Left margin (12) + 3840 = 3856
 * Active V: [OB (8) + 2166 + VBP (50)] * 2 exposures = 4448
 */
static imx274_reg mode_3840X2160_dol_30fps[] = {
	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{0x3000, 0x12},
	/*MCLK 24MHz */
	{0x3120, 0xF0},
	{0x3121, 0x00},
	{0x3122, 0x02},
	{0x3129, 0x9C},
	{0x312A, 0x02},
	{0x312D, 0x02},
	{0x310B, 0x00},
	{0x304C, 0x00},
	{0x304D, 0x03},
	{0x331C, 0x1A},
	{0x331D, 0x00},
	{0x3502, 0x02},
	{0x3529, 0x0E},
	{0x352A, 0x0E},
	{0x352B, 0x0E},
	{0x3538, 0x0E},
	{0x3539, 0x0E},
	{0x3553, 0x00},
	{0x357D, 0x05},
	{0x357F, 0x05},
	{0x3581, 0x04},
	{0x3583, 0x76},
	{0x3587, 0x01},
	{0x35BB, 0x0E},
	{0x35BC, 0x0E},
	{0x35BD, 0x0E},
	{0x35BE, 0x0E},
	{0x35BF, 0x0E},
	{0x366E, 0x00},
	{0x366F, 0x00},
	{0x3670, 0x00},
	{0x3671, 0x00},
	{0x30EE, 0x01},
	{0x3304, 0x32},
	{0x3305, 0x00},
	{0x3306, 0x32},
	{0x3307, 0x00},
	{0x3590, 0x32},
	{0x3391, 0x00},
	{0x3686, 0x32},
	{0x3687, 0x00},

	/*Mode Setting*/
	{0x3004, 0x06},
	{0x3005, 0x01},
	{0x3006, 0x00},
	{0x3007, 0xA2}, /* [7:5] is set to 0x5 to enable VWINPOS cropping. */
	{0x300C, 0x06}, /* SHR: Minimum 6 */
	{0x300D, 0x00},
	{0x300E, 0x00},
	{0x3019, 0x31},
	{0x301A, 0x00},
	{0x302E, 0x06},
	{0x302F, 0x00},
	{0x3030, 0x80},
	{0x3031, 0x01},
	{0x3032, 0x32},
	{0x3033, 0x00},
	{0x3041, 0x31},
	{0x3042, 0x07},
	{0x3043, 0x01},
	{0x306B, 0x05},
	{0x30E2, 0x01},
	{0x30E9, 0x01},
	{0x30F6, 0x1C},
	{0x30F7, 0x04},
	{0x30F8, 0xEC},
	{0x30F9, 0x08},
	{0x30FA, 0x00},
	{0x3037, 0x01},
	{0x3038, 0x00}, /* Note that the 12 "margin" pixels are NOT cropped here. */
					/* They will be cropped by CSI along with LI pixels. */
					/* This is a WAR for CSI cropping alignment requirements. */
	{0x3039, 0x00},
	{0x303A, 0x0C},
	{0x303B, 0x0F},
	{0x30DD, 0x01},
	{0x30DE, 0x04}, /* VWIDCUT: Crop 4 margin rows from the top and bottom. */
	{0x30DF, 0x00},
	{0x30E0, 0x03}, /* VWINPOS: Crop after 6 ignored area rows (VWINPOS * 2) */
	{0x30E1, 0x00},
	{0x3130, 0x7E}, /* WRITE_VSIZE: 2174 = post-crop size (2166) + OB (8) */
	{0x3131, 0x08},
	{0x3132, 0xA8}, /* Y_OUT_SIZE: 2216 = post-crop (2166) + RHS (50) */
	{0x3133, 0x08},
	{0x3342, 0x0A},
	{0x3343, 0x00},
	{0x3344, 0x16},
	{0x3345, 0x00},
	{0x33A6, 0x01},
	{0x3528, 0x0E},
	{0x3554, 0x1F},
	{0x3555, 0x01},
	{0x3556, 0x01},
	{0x3557, 0x01},
	{0x3558, 0x01},
	{0x3559, 0x00},
	{0x355A, 0x00},
	{0x35BA, 0x0E},
	{0x366A, 0x1B},
	{0x366B, 0x1A},
	{0x366C, 0x19},
	{0x366D, 0x17},
	{0x3A41, 0x08},

	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{IMX274_TABLE_END, 0x0000}
};

/* Mode 3(DOL) : 1920x1080 10 bits 60fps DOL-HDR
 * Active H: LI (4) + Left margin (6) + 1920 + Right margin (6) = 1936
 * Active V: [OB (8) + 1086 + VBP (38)] * 2 exposures = 2264
 */
static imx274_reg mode_1920X1080_dol_60fps[] = {
	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{0x3000, 0x12},
	/*MCLK 24MHz */
	{0x3120, 0xF0},
	{0x3121, 0x00},
	{0x3122, 0x02},
	{0x3129, 0x9C},
	{0x312A, 0x02},
	{0x312D, 0x02},
	{0x310B, 0x00},
	{0x304C, 0x00},
	{0x304D, 0x03},
	{0x331C, 0x1A},
	{0x331D, 0x00},
	{0x3502, 0x02},
	{0x3529, 0x0E},
	{0x352A, 0x0E},
	{0x352B, 0x0E},
	{0x3538, 0x0E},
	{0x3539, 0x0E},
	{0x3553, 0x00},
	{0x357D, 0x05},
	{0x357F, 0x05},
	{0x3581, 0x04},
	{0x3583, 0x76},
	{0x3587, 0x01},
	{0x35BB, 0x0E},
	{0x35BC, 0x0E},
	{0x35BD, 0x0E},
	{0x35BE, 0x0E},
	{0x35BF, 0x0E},
	{0x366E, 0x00},
	{0x366F, 0x00},
	{0x3670, 0x00},
	{0x3671, 0x00},
	{0x30EE, 0x01},
	{0x3304, 0x32},
	{0x3305, 0x00},
	{0x3306, 0x32},
	{0x3307, 0x00},
	{0x3590, 0x32},
	{0x3391, 0x00},
	{0x3686, 0x32},
	{0x3687, 0x00},

	/*Mode Setting*/
	{0x3004, 0x07},
	{0x3005, 0x21},
	{0x3006, 0x00},
	{0x3007, 0xB1},
	{0x300C, 0x04}, /* SHR: Minimum 4 */
	{0x300D, 0x00},
	{0x300E, 0x00},
	{0x3019, 0x31},
	{0x301A, 0x00},
	{0x302E, 0x06},
	{0x302F, 0x00},
	{0x3030, 0x10},
	{0x3031, 0x00},
	{0x3032, 0x26},
	{0x3033, 0x00},
	{0x3041, 0x31},
	{0x3042, 0x04},
	{0x3043, 0x01},
	{0x306B, 0x05},
	{0x30E2, 0x02},
	{0x30E9, 0x01},
	{0x30F6, 0x1C}, /* HMAX */
	{0x30F7, 0x04},
	{0x30F8, 0x83},
	{0x30F9, 0x04},
	{0x30FA, 0x00},
	{0x30EE, 0x01},
	{0x30DD, 0x01},
	{0x30DE, 0x04}, /* VWIDCUT */
	{0x30DF, 0x00},
	{0x30E0, 0x03}, /* VWINPOS */
	{0x30E1, 0x00},
	{0x3037, 0x01},
	{0x3038, 0x00}, /* HTRIM (6 left and 6 right margin pixels output) */
	{0x3039, 0x00},
	{0x303A, 0x18},
	{0x303B, 0x0F},
	{0x3130, 0x46}, /* WRITE_VSIZE: 1094 = post-crop size (1086) + OB (8)*/
	{0x3131, 0x04},
	{0x3132, 0x64}, /* Y_OUT_SIZE: 1124 = post-crop (1086) + RHS1 (38)*/
	{0x3133, 0x04},
	{0x3342, 0x0A},
	{0x3343, 0x00},
	{0x3344, 0x1A},
	{0x3345, 0x00},
	{0x33A6, 0x01},
	{0x3528, 0x0E},
	{0x3554, 0x00},
	{0x3555, 0x01},
	{0x3556, 0x01},
	{0x3557, 0x01},
	{0x3558, 0x01},
	{0x3559, 0x00},
	{0x355A, 0x00},
	{0x35BA, 0x0E},
	{0x366A, 0x1B},
	{0x366B, 0x1A},
	{0x366C, 0x19},
	{0x366D, 0x17},
	{0x3A41, 0x08},

	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{IMX274_TABLE_END, 0x0000}
};

/* Mode 3 : 1920X1080 10 bits 60fps*/
static imx274_reg mode_1920X1080[] = {
	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{0x3000, 0x12}, /* mode select streaming on */
	/* input freq. 24M */
	{0x3120, 0xF0},
	{0x3122, 0x02},
	{0x3129, 0x9c},
	{0x312A, 0x02},
	{0x312D, 0x02},

	{0x310B, 0x00},
	{0x304C, 0x00},
	{0x304D, 0x03},
	{0x331C, 0x1A},
	{0x3502, 0x02},
	{0x3529, 0x0E},
	{0x352A, 0x0E},
	{0x352B, 0x0E},
	{0x3538, 0x0E},
	{0x3539, 0x0E},
	{0x3553, 0x00},
	{0x357D, 0x05},
	{0x357F, 0x05},
	{0x3581, 0x04},
	{0x3583, 0x76},
	{0x3587, 0x01},
	{0x35BB, 0x0E},
	{0x35BC, 0x0E},
	{0x35BD, 0x0E},
	{0x35BE, 0x0E},
	{0x35BF, 0x0E},
	{0x366E, 0x00},
	{0x366F, 0x00},
	{0x3670, 0x00},
	{0x3671, 0x00},
	{0x30EE, 0x01},
	{0x3304, 0x32},
	{0x3306, 0x32},
	{0x3590, 0x32},
	{0x3686, 0x32},
	/* resolution */
	{0x30E2, 0x02},
	{0x30F6, 0x04},
	{0x30F7, 0x01},
	{0x30F8, 0x0C},
	{0x30F9, 0x12},
	{0x3130, 0x40},
	{0x3131, 0x04},
	{0x3132, 0x38},
	{0x3133, 0x04},

	/* crop */
	{0x30DD, 0x01},
	{0x30DE, 0x07},
	{0x30DF, 0x00},
	{0x30E0, 0x04},
	{0x30E1, 0x00},
	{0x3037, 0x01},
	{0x3038, 0x0C},
	{0x3039, 0x00},
	{0x303A, 0x0C},
	{0x303B, 0x0F},

	/* mode setting */
	{0x3004, 0x02},
	{0x3005, 0x21},
	{0x3006, 0x00},
	{0x3007, 0xB1},
	{0x300C, 0x08}, /* SHR: Minimum 8 */
	{0x300D, 0x00},
	{0x3019, 0x00},
	{0x3A41, 0x08},
	{0x3342, 0x0A},
	{0x3343, 0x00},
	{0x3344, 0x1A},
	{0x3345, 0x00},
	{0x3528, 0x0E},
	{0x3554, 0x00},
	{0x3555, 0x01},
	{0x3556, 0x01},
	{0x3557, 0x01},
	{0x3558, 0x01},
	{0x3559, 0x00},
	{0x355A, 0x00},
	{0x35BA, 0x0E},
	{0x366A, 0x1B},
	{0x366B, 0x1A},
	{0x366C, 0x19},
	{0x366D, 0x17},
	{0x33A6, 0x01},
	{0x306B, 0x05},

	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{IMX274_TABLE_END, 0x0000}
};

/* Mode 5 : 1288X546 10 bits 240fps*/
static const imx274_reg mode_1288x546[] = {
	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{0x3000, 0x12}, /* mode select streaming on */
	/* input freq. 24M */
	{0x3120, 0xF0},
	{0x3122, 0x02},
	{0x3129, 0x9c},
	{0x312A, 0x02},
	{0x312D, 0x02},

	{0x310B, 0x00},
	{0x304C, 0x00},
	{0x304D, 0x03},
	{0x331C, 0x1A},
	{0x3502, 0x02},
	{0x3529, 0x0E},
	{0x352A, 0x0E},
	{0x352B, 0x0E},
	{0x3538, 0x0E},
	{0x3539, 0x0E},
	{0x3553, 0x00},
	{0x357D, 0x05},
	{0x357F, 0x05},
	{0x3581, 0x04},
	{0x3583, 0x76},
	{0x3587, 0x01},
	{0x35BB, 0x0E},
	{0x35BC, 0x0E},
	{0x35BD, 0x0E},
	{0x35BE, 0x0E},
	{0x35BF, 0x0E},
	{0x366E, 0x00},
	{0x366F, 0x00},
	{0x3670, 0x00},
	{0x3671, 0x00},
	{0x30EE, 0x01},
	{0x3304, 0x32},
	{0x3306, 0x32},
	{0x3590, 0x32},
	{0x3686, 0x32},
	/* resolution */
	{0x30E2, 0x04},
	{0x30F6, 0x04}, /* HMAX 260 */
	{0x30F7, 0x01}, /* HMAX */
	{0x30F8, 0x83}, /* VMAX 1155 */
	{0x30F9, 0x04}, /* VMAX */
	{0x30FA, 0x00}, /* VMAX */
	{0x3130, 0x26},
	{0x3131, 0x02},
	{0x3132, 0x22},
	{0x3133, 0x02},
	/* mode setting */
	{0x3004, 0x04},
	{0x3005, 0x31},
	{0x3006, 0x00},
	{0x3007, 0x02},
	{0x300C, 0x04}, /* SHR: Minimum 4 */
	{0x300D, 0x00},
	{0x3019, 0x00},
	{0x3A41, 0x04},
	{0x3342, 0x0A},
	{0x3343, 0x00},
	{0x3344, 0x1A},
	{0x3345, 0x00},
	{0x3528, 0x0E},
	{0x3554, 0x00},
	{0x3555, 0x01},
	{0x3556, 0x01},
	{0x3557, 0x01},
	{0x3558, 0x01},
	{0x3559, 0x00},
	{0x355A, 0x00},
	{0x35BA, 0x0E},
	{0x366A, 0x1B},
	{0x366B, 0x19},
	{0x366C, 0x17},
	{0x366D, 0x17},
	{0x33A6, 0x01},
	{0x306B, 0x05},

	{IMX274_TABLE_WAIT_MS, IMX274_WAIT_MS},
	{IMX274_TABLE_END, 0x0000}
};

enum {
	IMX274_MODE_3840X2160,
	IMX274_MODE_1920X1080,
	IMX274_MODE_3840X2160_DOL_30FPS,
	IMX274_MODE_1920X1080_DOL_60FPS,
	IMX274_MODE_1288X546,
	IMX274_MODE_START_STREAM,
	IMX274_MODE_STOP_STREAM,
	IMX274_MODE_TEST_PATTERN,
};

static const imx274_reg *mode_table[] = {
	[IMX274_MODE_3840X2160] = mode_3840X2160_60fps,
	[IMX274_MODE_1920X1080] = mode_1920X1080,
	[IMX274_MODE_3840X2160_DOL_30FPS] = mode_3840X2160_dol_30fps,
	[IMX274_MODE_1920X1080_DOL_60FPS] = mode_1920X1080_dol_60fps,
	[IMX274_MODE_1288X546] = mode_1288x546,
	[IMX274_MODE_START_STREAM]		= imx274_start,
	[IMX274_MODE_STOP_STREAM]		= imx274_stop,
	[IMX274_MODE_TEST_PATTERN]		= tp_colorbars,
};

static const int imx274_30_fr[] = {
	30,
};

static const int imx274_60_fr[] = {
	60,
};

static const int imx274_240_fr[] = {
	240,
};

static const struct camera_common_frmfmt imx274_frmfmt[] = {
	{{3840, 2160}, imx274_60_fr, 1, 0, IMX274_MODE_3840X2160},
	{{1920, 1080}, imx274_60_fr, 1, 0, IMX274_MODE_1920X1080},
	{{3856, 4448}, imx274_30_fr, 1, 1, IMX274_MODE_3840X2160_DOL_30FPS},
	{{1936, 2264}, imx274_60_fr, 1, 1, IMX274_MODE_1920X1080_DOL_60FPS},
#if ENABLE_EXTRA_MODES
	{{1288, 546}, imx274_240_fr, 1, 0, IMX274_MODE_1288X546},
#endif
};
#endif  /* __IMX274_I2C_TABLES__ */
