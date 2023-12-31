/* SPDX-License-Identifier: GPL-2.0 */
/*
 * imx185_mode_tbls.h - imx274 sensor driver
 *
 * Copyright (c) 2016-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef __IMX185_I2C_TABLES__
#define __IMX185_I2C_TABLES__

#include <media/camera_common.h>
#include <linux/miscdevice.h>

#define IMX185_TABLE_WAIT_MS	0
#define IMX185_TABLE_END	1
#define IMX185_MAX_RETRIES	3
#define IMX185_WAIT_MS_STOP	1
#define IMX185_WAIT_MS_START	30
#define IMX185_WAIT_MS_STREAM	210
#define IMX185_GAIN_TABLE_SIZE 255

/* #define INIT_ET_INSETTING 1 */

#define imx185_reg struct reg_8

static imx185_reg imx185_start[] = {
	{0x3000, 0x00 },
	{IMX185_TABLE_WAIT_MS, IMX185_WAIT_MS_START},
	{0x3002, 0x00},
	{0x3049, 0x02},
	{IMX185_TABLE_WAIT_MS, IMX185_WAIT_MS_STREAM},
	{ IMX185_TABLE_END, 0x00 }
};

static imx185_reg imx185_stop[] = {
	{0x3000, 0x01 },
	{IMX185_TABLE_WAIT_MS, IMX185_WAIT_MS_STOP},
	{IMX185_TABLE_END, 0x00 }
};

static imx185_reg tp_colorbars[] = {
	{0x300A, 0x00},/*BLC for PG*/
	{0x300E, 0x00},
	{0x3089, 0x00},
	{0x308C, 0x13},
	/*
	 * bit 0: PG mode enable
	 * bit 1: Back Ground Transient:
	 * bit [4-7]: PG mode setting, Set at 0h to Fh, suggest 1 or 5
	 * raw12 max output FFEh
	 */
	{IMX185_TABLE_WAIT_MS, IMX185_WAIT_MS_STOP},
	{IMX185_TABLE_END, 0x00}
};

static  imx185_reg imx185_1920x1080_crop_60fps[] = {
	{0x3002, 0x01},
	{0x3005, 0x01},
	{0x3006, 0x00},
	{0x3007, 0x50},
	{0x3009, 0x01},
	{0x300a, 0xf0},
	{0x300f, 0x01},
	{0x3018, 0x65},
	{0x3019, 0x04},
	{0x301b, 0x4c},
	{0x301c, 0x04},
	{0x301d, 0x08},
	{0x301e, 0x02},

	{0x3036, 0x06},
	{0x3038, 0x08},
	{0x3039, 0x00},
	{0x303a, 0x40},
	{0x303b, 0x04},
	{0x303c, 0x0c},
	{0x303d, 0x00},
	{0x303e, 0x7c},
	{0x303f, 0x07},

	{0x3044, 0xe1},
	{0x3048, 0x33},

	{0x305C, 0x20},
	{0x305D, 0x00},
	{0x305E, 0x18},
	{0x305F, 0x00},
	{0x3063, 0x74},

	{0x3084, 0x0f},
	{0x3086, 0x10},
	{0x30A1, 0x44},
	{0x30cf, 0xe1},
	{0x30d0, 0x29},
	{0x30d2, 0x9b},
	{0x30d3, 0x01},

	{0x311d, 0x0a},
	{0x3123, 0x0f},
	{0x3126, 0xdf},
	{0x3147, 0x87},
	{0x31e0, 0x01},
	{0x31e1, 0x9e},
	{0x31e2, 0x01},
	{0x31e5, 0x05},
	{0x31e6, 0x05},
	{0x31e7, 0x3a},
	{0x31e8, 0x3a},

	{0x3203, 0xc8},
	{0x3207, 0x54},
	{0x3213, 0x16},
	{0x3215, 0xf6},
	{0x321a, 0x14},
	{0x321b, 0x51},
	{0x3229, 0xe7},
	{0x322a, 0xf0},
	{0x322b, 0x10},
	{0x3231, 0xe7},
	{0x3232, 0xf0},
	{0x3233, 0x10},
	{0x323c, 0xe8},
	{0x323d, 0x70},
	{0x3243, 0x08},
	{0x3244, 0xe1},
	{0x3245, 0x10},
	{0x3247, 0xe7},
	{0x3248, 0x60},
	{0x3249, 0x1e},
	{0x324b, 0x00},
	{0x324c, 0x41},
	{0x3250, 0x30},
	{0x3251, 0x0a},
	{0x3252, 0xff},
	{0x3253, 0xff},
	{0x3254, 0xff},
	{0x3255, 0x02},
	{0x3257, 0xf0},
	{0x325a, 0xa6},
	{0x325d, 0x14},
	{0x325e, 0x51},
	{0x3260, 0x00},
	{0x3261, 0x61},
	{0x3266, 0x30},
	{0x3267, 0x05},
	{0x3275, 0xe7},
	{0x3281, 0xea},
	{0x3282, 0x70},
	{0x3285, 0xff},
	{0x328a, 0xf0},
	{0x328d, 0xb6},
	{0x328e, 0x40},
	{0x3290, 0x42},
	{0x3291, 0x51},
	{0x3292, 0x1e},
	{0x3294, 0xc4},
	{0x3295, 0x20},
	{0x3297, 0x50},
	{0x3298, 0x31},
	{0x3299, 0x1f},
	{0x329b, 0xc0},
	{0x329c, 0x60},
	{0x329e, 0x4c},
	{0x329f, 0x71},
	{0x32a0, 0x1f},
	{0x32a2, 0xb6},
	{0x32a3, 0xc0},
	{0x32a4, 0x0b},
	{0x32a9, 0x24},
	{0x32aa, 0x41},
	{0x32b0, 0x25},
	{0x32b1, 0x51},
	{0x32b7, 0x1c},
	{0x32b8, 0xc1},
	{0x32b9, 0x12},
	{0x32be, 0x1d},
	{0x32bf, 0xd1},
	{0x32c0, 0x12},
	{0x32c2, 0xa8},
	{0x32c3, 0xc0},
	{0x32c4, 0x0a},
	{0x32c5, 0x1e},
	{0x32c6, 0x21},
	{0x32c9, 0xb0},
	{0x32ca, 0x40},
	{0x32cc, 0x26},
	{0x32cd, 0xa1},
	{0x32d0, 0xb6},
	{0x32d1, 0xc0},
	{0x32d2, 0x0b},
	{0x32d4, 0xe2},
	{0x32d5, 0x40},
	{0x32d8, 0x4e},
	{0x32d9, 0xa1},
	{0x32ec, 0xf0},

	{0x3303, 0x00},
	{0x3305, 0x03},
	{0x3314, 0x04},
	{0x3315, 0x01},
	{0x3316, 0x04},
	{0x3317, 0x04},
	{0x3318, 0x38},
	{0x3319, 0x04},
	{0x332c, 0x40},
	{0x332d, 0x20},
	{0x332e, 0x03},
	{0x333e, 0x0c},
	{0x333f, 0x0c},
	{0x3340, 0x03},
	{0x3341, 0x20},
	{0x3342, 0x25},
	{0x3343, 0x68},
	{0x3344, 0x20},
	{0x3345, 0x40},
	{0x3346, 0x28},
	{0x3347, 0x20},
	{0x3348, 0x18},
	{0x3349, 0x78},
	{0x334a, 0x28},
	{0x334e, 0xb4},
	{0x334f, 0x01},
#ifdef INIT_ET_INSETTING
	{0x3020, 0xe1},
	{0x3021, 0x04},
#endif
	{IMX185_TABLE_END, 0x00}
};

static  imx185_reg imx185_1920x1080_crop_30fps[] = {
	{0x3002, 0x01},
	{0x3005, 0x01},
	{0x3006, 0x00},
	{0x3007, 0x50},
	{0x3009, 0x02},
	{0x300a, 0xf0},
	{0x300f, 0x01},
	{0x3018, 0x65},
	{0x3019, 0x04},
	{0x301b, 0x89},
	{0x301c, 0x08},
	{0x301d, 0x08},
	{0x301e, 0x02},

	{0x3036, 0x06},
	{0x3038, 0x08},
	{0x3039, 0x00},
	{0x303a, 0x40},
	{0x303b, 0x04},
	{0x303c, 0x0c},
	{0x303d, 0x00},
	{0x303e, 0x7c},
	{0x303f, 0x07},

	{0x3048, 0x33},

	{0x305C, 0x20},
	{0x305D, 0x00},
	{0x305E, 0x18},
	{0x305F, 0x00},
	{0x3063, 0x74},

	{0x3084, 0x0f},
	{0x3086, 0x10},
	{0x30cf, 0xe1},
	{0x30d0, 0x29},
	{0x30d2, 0x9b},
	{0x30d3, 0x01},

	{0x311d, 0x0a},
	{0x3123, 0x0f},
	{0x3126, 0xdf},
	{0x3147, 0x87},
	{0x31e0, 0x01},
	{0x31e1, 0x9e},
	{0x31e2, 0x01},
	{0x31e5, 0x05},
	{0x31e6, 0x05},
	{0x31e7, 0x3a},
	{0x31e8, 0x3a},

	{0x3203, 0xc8},
	{0x3207, 0x54},
	{0x3213, 0x16},
	{0x3215, 0xf6},
	{0x321a, 0x14},
	{0x321b, 0x51},
	{0x3229, 0xe7},
	{0x322a, 0xf0},
	{0x322b, 0x10},
	{0x3231, 0xe7},
	{0x3232, 0xf0},
	{0x3233, 0x10},
	{0x323c, 0xe8},
	{0x323d, 0x70},
	{0x3243, 0x08},
	{0x3244, 0xe1},
	{0x3245, 0x10},
	{0x3247, 0xe7},
	{0x3248, 0x60},
	{0x3249, 0x1e},
	{0x324b, 0x00},
	{0x324c, 0x41},
	{0x3250, 0x30},
	{0x3251, 0x0a},
	{0x3252, 0xff},
	{0x3253, 0xff},
	{0x3254, 0xff},
	{0x3255, 0x02},
	{0x3257, 0xf0},
	{0x325a, 0xa6},
	{0x325d, 0x14},
	{0x325e, 0x51},
	{0x3260, 0x00},
	{0x3261, 0x61},
	{0x3266, 0x30},
	{0x3267, 0x05},
	{0x3275, 0xe7},
	{0x3281, 0xea},
	{0x3282, 0x70},
	{0x3285, 0xff},
	{0x328a, 0xf0},
	{0x328d, 0xb6},
	{0x328e, 0x40},
	{0x3290, 0x42},
	{0x3291, 0x51},
	{0x3292, 0x1e},
	{0x3294, 0xc4},
	{0x3295, 0x20},
	{0x3297, 0x50},
	{0x3298, 0x31},
	{0x3299, 0x1f},
	{0x329b, 0xc0},
	{0x329c, 0x60},
	{0x329e, 0x4c},
	{0x329f, 0x71},
	{0x32a0, 0x1f},
	{0x32a2, 0xb6},
	{0x32a3, 0xc0},
	{0x32a4, 0x0b},
	{0x32a9, 0x24},
	{0x32aa, 0x41},
	{0x32b0, 0x25},
	{0x32b1, 0x51},
	{0x32b7, 0x1c},
	{0x32b8, 0xc1},
	{0x32b9, 0x12},
	{0x32be, 0x1d},
	{0x32bf, 0xd1},
	{0x32c0, 0x12},
	{0x32c2, 0xa8},
	{0x32c3, 0xc0},
	{0x32c4, 0x0a},
	{0x32c5, 0x1e},
	{0x32c6, 0x21},
	{0x32c9, 0xb0},
	{0x32ca, 0x40},
	{0x32cc, 0x26},
	{0x32cd, 0xa1},
	{0x32d0, 0xb6},
	{0x32d1, 0xc0},
	{0x32d2, 0x0b},
	{0x32d4, 0xe2},
	{0x32d5, 0x40},
	{0x32d8, 0x4e},
	{0x32d9, 0xa1},
	{0x32ec, 0xf0},

	{0x3303, 0x10},
	{0x3305, 0x03},
	{0x3314, 0x04},
	{0x3315, 0x01},
	{0x3316, 0x04},
	{0x3317, 0x04},
	{0x3318, 0x38},
	{0x3319, 0x04},
	{0x332c, 0x30},
	{0x332d, 0x20},
	{0x332e, 0x03},
	{0x333e, 0x0c},
	{0x333f, 0x0c},
	{0x3340, 0x03},
	{0x3341, 0x20},
	{0x3342, 0x25},
	{0x3343, 0x58},
	{0x3344, 0x10},
	{0x3345, 0x30},
	{0x3346, 0x18},
	{0x3347, 0x10},
	{0x3348, 0x10},
	{0x3349, 0x48},
	{0x334a, 0x28},
	{0x334e, 0xb4},
	{0x334f, 0x01},
#ifdef INIT_ET_INSETTING
	{0x3020, 0xe1},
	{0x3021, 0x04},
#endif
	{IMX185_TABLE_END, 0x00}
};

static imx185_reg imx185_1920x1080_hdr_crop_30fps[] = {
	{0x3002, 0x01},
	{0x3005, 0x01},
	{0x3006, 0x00},
	{0x3007, 0x50},
	{0x3009, 0x02},
	{0x300a, 0xf0},

	{0x300c, 0x02},
	{0x300f, 0x01},
	{0x3010, 0x38},
	{0x3011, 0x00},
	{0x3012, 0x0f},
	{0x3013, 0x00},

	{0x3018, 0x65},
	{0x3019, 0x04},
	{0x301b, 0x98},
	{0x301c, 0x08},
	{0x301d, 0x08},
	{0x301e, 0x02},

	{0x3036, 0x06},
	{0x3038, 0x08},
	{0x3039, 0x00},
	{0x303a, 0x40},
	{0x303b, 0x04},
	{0x303c, 0x0c},
	{0x303d, 0x00},
	{0x303e, 0x7c},
	{0x303f, 0x07},

	{0x3044, 0xe1},
	{0x3048, 0x33},
#ifdef INIT_ET_INSETTING
	{0x3020, 0x1F},/*SHS1 1055, coarse 69*/
	{0x3021, 0x04},
	{0x3022, 0x00},
	{0x3023, 0x12},/*SHS2 18, coarse 1106*/
	{0x3024, 0x00},
	{0x3025, 0x00},
#endif
	{0x3056, 0xc9},
	{0x3057, 0x64},

	{0x305C, 0x20},
	{0x305D, 0x00},
	{0x305E, 0x18},
	{0x305F, 0x00},
	{0x3063, 0x74},

	{0x3065, 0x00},

	{0x3084, 0x0f},
	{0x3086, 0x10},
	{0x30cf, 0xe1},
	{0x30d0, 0x29},
	{0x30d2, 0x9b},
	{0x30d3, 0x01},

	{0x311d, 0x0a},
	{0x3123, 0x0f},
	{0x3126, 0xdf},
	{0x3147, 0x87},
	{0x31e0, 0x01},
	{0x31e1, 0x9e},
	{0x31e2, 0x01},
	{0x31e5, 0x05},
	{0x31e6, 0x05},
	{0x31e7, 0x3a},
	{0x31e8, 0x3a},

	{0x3203, 0xc8},
	{0x3207, 0x54},
	{0x3213, 0x16},
	{0x3215, 0xf6},
	{0x321a, 0x14},
	{0x321b, 0x51},
	{0x3229, 0xe7},
	{0x322a, 0xf0},
	{0x322b, 0x10},
	{0x3231, 0xe7},
	{0x3232, 0xf0},
	{0x3233, 0x10},
	{0x323c, 0xe8},
	{0x323d, 0x70},
	{0x3243, 0x08},
	{0x3244, 0xe1},
	{0x3245, 0x10},
	{0x3247, 0xe7},
	{0x3248, 0x60},
	{0x3249, 0x1e},
	{0x324b, 0x00},
	{0x324c, 0x41},
	{0x3250, 0x30},
	{0x3251, 0x0a},
	{0x3252, 0xff},
	{0x3253, 0xff},
	{0x3254, 0xff},
	{0x3255, 0x02},
	{0x3257, 0xf0},
	{0x325a, 0xa6},
	{0x325d, 0x14},
	{0x325e, 0x51},
	{0x3260, 0x00},
	{0x3261, 0x61},
	{0x3266, 0x30},
	{0x3267, 0x05},
	{0x3275, 0xe7},
	{0x3281, 0xea},
	{0x3282, 0x70},
	{0x3285, 0xff},
	{0x328a, 0xf0},
	{0x328d, 0xb6},
	{0x328e, 0x40},
	{0x3290, 0x42},
	{0x3291, 0x51},
	{0x3292, 0x1e},
	{0x3294, 0xc4},
	{0x3295, 0x20},
	{0x3297, 0x50},
	{0x3298, 0x31},
	{0x3299, 0x1f},
	{0x329b, 0xc0},
	{0x329c, 0x60},
	{0x329e, 0x4c},
	{0x329f, 0x71},
	{0x32a0, 0x1f},
	{0x32a2, 0xb6},
	{0x32a3, 0xc0},
	{0x32a4, 0x0b},
	{0x32a9, 0x24},
	{0x32aa, 0x41},
	{0x32b0, 0x25},
	{0x32b1, 0x51},
	{0x32b7, 0x1c},
	{0x32b8, 0xc1},
	{0x32b9, 0x12},
	{0x32be, 0x1d},
	{0x32bf, 0xd1},
	{0x32c0, 0x12},
	{0x32c2, 0xa8},
	{0x32c3, 0xc0},
	{0x32c4, 0x0a},
	{0x32c5, 0x1e},
	{0x32c6, 0x21},
	{0x32c9, 0xb0},
	{0x32ca, 0x40},
	{0x32cc, 0x26},
	{0x32cd, 0xa1},
	{0x32d0, 0xb6},
	{0x32d1, 0xc0},
	{0x32d2, 0x0b},
	{0x32d4, 0xe2},
	{0x32d5, 0x40},
	{0x32d8, 0x4e},
	{0x32d9, 0xa1},
	{0x32ec, 0xf0},

	{0x3303, 0x10},
	{0x3305, 0x03},
	{0x3314, 0x04},
	{0x3315, 0x01},
	{0x3316, 0x04},
	{0x3317, 0x04},
	{0x3318, 0x38},
	{0x3319, 0x04},
	{0x332c, 0x30},
	{0x332d, 0x20},
	{0x332e, 0x03},
	{0x333e, 0x0c},
	{0x333f, 0x0c},
	{0x3340, 0x03},

	{0x3341, 0x20},
	{0x3342, 0x25},
	{0x3343, 0x58},
	{0x3344, 0x10},
	{0x3345, 0x30},
	{0x3346, 0x18},
	{0x3347, 0x10},
	{0x3348, 0x10},
	{0x3349, 0x48},
	{0x334a, 0x28},
	{0x334e, 0xb4},
	{0x334f, 0x01},

#ifdef INIT_ET_INSETTING
	{0x3020, 0x1F},
	{0x3021, 0x04},
	{0x3022, 0x00},
	{0x3023, 0x12},
	{0x3024, 0x00},
	{0x3025, 0x00},
#endif
	{0x300C, 0x02},
	{0x300F, 0x05},
	{0x3010, 0x38},
	{0x3012, 0x0F},
	{0x3084, 0x0F},
	{0x3065, 0x00},
	{IMX185_TABLE_END, 0x00}
};

static imx185_reg imx185_1920x1080_crop_10bit_60fps[] = {
	{0x3002, 0x01},
	{0x3005, 0x00},/*10BIT*/
	{0x3006, 0x00},
	{0x3007, 0x50},
	{0x3009, 0x01},
	{0x300a, 0x3c},/*10BIT*/
	{0x300f, 0x01},
	{0x3018, 0x65},
	{0x3019, 0x04},
	{0x301b, 0x4c},
	{0x301c, 0x04},
	{0x301d, 0x08},
	{0x301e, 0x02},

	{0x3036, 0x06},
	{0x3038, 0x08},
	{0x3039, 0x00},
	{0x303a, 0x40},
	{0x303b, 0x04},
	{0x303c, 0x0c},
	{0x303d, 0x00},
	{0x303e, 0x7c},
	{0x303f, 0x07},

	{0x3044, 0xe1},
	{0x3048, 0x33},

	{0x305C, 0x20},
	{0x305D, 0x00},
	{0x305E, 0x18},
	{0x305F, 0x00},
	{0x3063, 0x74},

	{0x3084, 0x0f},
	{0x3086, 0x10},
	{0x30A1, 0x44},
	{0x30cf, 0xe1},
	{0x30d0, 0x29},
	{0x30d2, 0x9b},
	{0x30d3, 0x01},

	{0x311d, 0x0a},
	{0x3123, 0x0f},
	{0x3126, 0xdf},
	{0x3147, 0x87},
	{0x31e0, 0x01},
	{0x31e1, 0x9e},
	{0x31e2, 0x01},
	{0x31e5, 0x05},
	{0x31e6, 0x05},
	{0x31e7, 0x3a},
	{0x31e8, 0x3a},

	{0x3203, 0xc8},
	{0x3207, 0x54},
	{0x3213, 0x16},
	{0x3215, 0xf6},
	{0x321a, 0x14},
	{0x321b, 0x51},
	{0x3229, 0xe7},
	{0x322a, 0xf0},
	{0x322b, 0x10},
	{0x3231, 0xe7},
	{0x3232, 0xf0},
	{0x3233, 0x10},
	{0x323c, 0xe8},
	{0x323d, 0x70},
	{0x3243, 0x08},
	{0x3244, 0xe1},
	{0x3245, 0x10},
	{0x3247, 0xe7},
	{0x3248, 0x60},
	{0x3249, 0x1e},
	{0x324b, 0x00},
	{0x324c, 0x41},
	{0x3250, 0x30},
	{0x3251, 0x0a},
	{0x3252, 0xff},
	{0x3253, 0xff},
	{0x3254, 0xff},
	{0x3255, 0x02},
	{0x3257, 0xf0},
	{0x325a, 0xa6},
	{0x325d, 0x14},
	{0x325e, 0x51},
	{0x3260, 0x00},
	{0x3261, 0x61},
	{0x3266, 0x30},
	{0x3267, 0x05},
	{0x3275, 0xe7},
	{0x3281, 0xea},
	{0x3282, 0x70},
	{0x3285, 0xff},
	{0x328a, 0xf0},
	{0x328d, 0xb6},
	{0x328e, 0x40},
	{0x3290, 0x42},
	{0x3291, 0x51},
	{0x3292, 0x1e},
	{0x3294, 0xc4},
	{0x3295, 0x20},
	{0x3297, 0x50},
	{0x3298, 0x31},
	{0x3299, 0x1f},
	{0x329b, 0xc0},
	{0x329c, 0x60},
	{0x329e, 0x4c},
	{0x329f, 0x71},
	{0x32a0, 0x1f},
	{0x32a2, 0xb6},
	{0x32a3, 0xc0},
	{0x32a4, 0x0b},
	{0x32a9, 0x24},
	{0x32aa, 0x41},
	{0x32b0, 0x25},
	{0x32b1, 0x51},
	{0x32b7, 0x1c},
	{0x32b8, 0xc1},
	{0x32b9, 0x12},
	{0x32be, 0x1d},
	{0x32bf, 0xd1},
	{0x32c0, 0x12},
	{0x32c2, 0xa8},
	{0x32c3, 0xc0},
	{0x32c4, 0x0a},
	{0x32c5, 0x1e},
	{0x32c6, 0x21},
	{0x32c9, 0xb0},
	{0x32ca, 0x40},
	{0x32cc, 0x26},
	{0x32cd, 0xa1},
	{0x32d0, 0xb6},
	{0x32d1, 0xc0},
	{0x32d2, 0x0b},
	{0x32d4, 0xe2},
	{0x32d5, 0x40},
	{0x32d8, 0x4e},
	{0x32d9, 0xa1},
	{0x32ec, 0xf0},

	{0x3303, 0x00},
	{0x3305, 0x03},
	{0x3314, 0x04},
	{0x3315, 0x01},
	{0x3316, 0x04},
	{0x3317, 0x04},
	{0x3318, 0x38},
	{0x3319, 0x04},
	{0x332c, 0x40},
	{0x332d, 0x20},
	{0x332e, 0x03},
	{0x333e, 0x0a},/*10BIT*/
	{0x333f, 0x0a},/*10BIT*/
	{0x3340, 0x03},
	{0x3341, 0x20},
	{0x3342, 0x25},
	{0x3343, 0x68},
	{0x3344, 0x20},
	{0x3345, 0x40},
	{0x3346, 0x28},
	{0x3347, 0x20},
	{0x3348, 0x18},
	{0x3349, 0x78},
	{0x334a, 0x28},
	{0x334e, 0xb4},
	{0x334f, 0x01},
#ifdef INIT_ET_INSETTING
	{0x3020, 0xe1},
	{0x3021, 0x04},
#endif
	{IMX185_TABLE_END, 0x00}
};

static imx185_reg imx185_1920x1080_crop_10bit_30fps[] = {
	{0x3002, 0x01},
	{0x3005, 0x00},
	{0x3006, 0x00},
	{0x3007, 0x50},
	{0x3009, 0x02},
	{0x300a, 0x3c},
	{0x300f, 0x01},
	{0x3018, 0x65},
	{0x3019, 0x04},
	{0x301b, 0x98},
	{0x301c, 0x08},
	{0x301d, 0x08},
	{0x301e, 0x02},

	{0x3036, 0x06},
	{0x3038, 0x08},
	{0x3039, 0x00},
	{0x303a, 0x40},
	{0x303b, 0x04},
	{0x303c, 0x0c},
	{0x303d, 0x00},
	{0x303e, 0x7c},
	{0x303f, 0x07},

	{0x3044, 0xe1},
	{0x3048, 0x33},

	{0x305C, 0x20},
	{0x305D, 0x00},
	{0x305E, 0x18},
	{0x305F, 0x00},
	{0x3063, 0x74},

	{0x3084, 0x0f},
	{0x3086, 0x10},
	{0x30cf, 0xe1},
	{0x30d0, 0x29},
	{0x30d2, 0x9b},
	{0x30d3, 0x01},

	{0x311d, 0x0a},
	{0x3123, 0x0f},
	{0x3126, 0xdf},
	{0x3147, 0x87},
	{0x31e0, 0x01},
	{0x31e1, 0x9e},
	{0x31e2, 0x01},
	{0x31e5, 0x05},
	{0x31e6, 0x05},
	{0x31e7, 0x3a},
	{0x31e8, 0x3a},

	{0x3203, 0xc8},
	{0x3207, 0x54},
	{0x3213, 0x16},
	{0x3215, 0xf6},
	{0x321a, 0x14},
	{0x321b, 0x51},
	{0x3229, 0xe7},
	{0x322a, 0xf0},
	{0x322b, 0x10},
	{0x3231, 0xe7},
	{0x3232, 0xf0},
	{0x3233, 0x10},
	{0x323c, 0xe8},
	{0x323d, 0x70},
	{0x3243, 0x08},
	{0x3244, 0xe1},
	{0x3245, 0x10},
	{0x3247, 0xe7},
	{0x3248, 0x60},
	{0x3249, 0x1e},
	{0x324b, 0x00},
	{0x324c, 0x41},
	{0x3250, 0x30},
	{0x3251, 0x0a},
	{0x3252, 0xff},
	{0x3253, 0xff},
	{0x3254, 0xff},
	{0x3255, 0x02},
	{0x3257, 0xf0},
	{0x325a, 0xa6},
	{0x325d, 0x14},
	{0x325e, 0x51},
	{0x3260, 0x00},
	{0x3261, 0x61},
	{0x3266, 0x30},
	{0x3267, 0x05},
	{0x3275, 0xe7},
	{0x3281, 0xea},
	{0x3282, 0x70},
	{0x3285, 0xff},
	{0x328a, 0xf0},
	{0x328d, 0xb6},
	{0x328e, 0x40},
	{0x3290, 0x42},
	{0x3291, 0x51},
	{0x3292, 0x1e},
	{0x3294, 0xc4},
	{0x3295, 0x20},
	{0x3297, 0x50},
	{0x3298, 0x31},
	{0x3299, 0x1f},
	{0x329b, 0xc0},
	{0x329c, 0x60},
	{0x329e, 0x4c},
	{0x329f, 0x71},
	{0x32a0, 0x1f},
	{0x32a2, 0xb6},
	{0x32a3, 0xc0},
	{0x32a4, 0x0b},
	{0x32a9, 0x24},
	{0x32aa, 0x41},
	{0x32b0, 0x25},
	{0x32b1, 0x51},
	{0x32b7, 0x1c},
	{0x32b8, 0xc1},
	{0x32b9, 0x12},
	{0x32be, 0x1d},
	{0x32bf, 0xd1},
	{0x32c0, 0x12},
	{0x32c2, 0xa8},
	{0x32c3, 0xc0},
	{0x32c4, 0x0a},
	{0x32c5, 0x1e},
	{0x32c6, 0x21},
	{0x32c9, 0xb0},
	{0x32ca, 0x40},
	{0x32cc, 0x26},
	{0x32cd, 0xa1},
	{0x32d0, 0xb6},
	{0x32d1, 0xc0},
	{0x32d2, 0x0b},
	{0x32d4, 0xe2},
	{0x32d5, 0x40},
	{0x32d8, 0x4e},
	{0x32d9, 0xa1},
	{0x32ec, 0xf0},

	{0x3303, 0x10},
	{0x3305, 0x03},
	{0x3314, 0x04},
	{0x3315, 0x01},
	{0x3316, 0x04},
	{0x3317, 0x04},
	{0x3318, 0x38},
	{0x3319, 0x04},
	{0x332c, 0x30},
	{0x332d, 0x20},
	{0x332e, 0x03},
	{0x333e, 0x0a},
	{0x333f, 0x0a},
	{0x3340, 0x03},

	{0x3341, 0x20},
	{0x3342, 0x25},
	{0x3343, 0x58},
	{0x3344, 0x10},
	{0x3345, 0x30},
	{0x3346, 0x18},
	{0x3347, 0x10},
	{0x3348, 0x10},
	{0x3349, 0x48},
	{0x334a, 0x28},
	{0x334e, 0xb4},
	{0x334f, 0x01},
#ifdef INIT_ET_INSETTING
	{0x3020, 0xe1},
	{0x3021, 0x04},
#endif
	{IMX185_TABLE_END, 0x00}
};

enum {
	IMX185_MODE_1920X1080_CROP_30FPS,
	IMX185_MODE_1920X1080_CROP_10BIT_30FPS,
	IMX185_MODE_1920X1080_CROP_60FPS,
	IMX185_MODE_1920X1080_CROP_10BIT_60FPS,
	IMX185_MODE_1920X1080_CROP_HDR_30FPS,
	IMX185_MODE_START_STREAM,
	IMX185_MODE_STOP_STREAM,
	IMX185_MODE_TEST_PATTERN
};

static imx185_reg *mode_table[] = {
	[IMX185_MODE_1920X1080_CROP_30FPS] = imx185_1920x1080_crop_30fps,
	[IMX185_MODE_1920X1080_CROP_10BIT_30FPS] =
		imx185_1920x1080_crop_10bit_30fps,
	[IMX185_MODE_1920X1080_CROP_60FPS] = imx185_1920x1080_crop_60fps,
	[IMX185_MODE_1920X1080_CROP_10BIT_60FPS] =
		imx185_1920x1080_crop_10bit_60fps,
	[IMX185_MODE_1920X1080_CROP_HDR_30FPS] =
		imx185_1920x1080_hdr_crop_30fps,
	[IMX185_MODE_START_STREAM] = imx185_start,
	[IMX185_MODE_STOP_STREAM] = imx185_stop,
	[IMX185_MODE_TEST_PATTERN] = tp_colorbars,
};

static const int imx185_30fps[] = {
	30,
};

static const int imx185_60fps[] = {
	60,
};

/*
 * WARNING: frmfmt ordering need to match mode definition in
 * device tree!
 */
static const struct camera_common_frmfmt imx185_frmfmt[] = {
	{{1920, 1080}, imx185_30fps, 1, 0,
			IMX185_MODE_1920X1080_CROP_30FPS},
	{{1920, 1080}, imx185_30fps, 1, 0,
			IMX185_MODE_1920X1080_CROP_10BIT_30FPS},
	{{1920, 1080}, imx185_60fps, 1, 0,
			IMX185_MODE_1920X1080_CROP_60FPS},
	{{1920, 1080}, imx185_60fps, 1, 0,
			IMX185_MODE_1920X1080_CROP_10BIT_60FPS},
	{{1920, 1080}, imx185_30fps, 1, 1,
			IMX185_MODE_1920X1080_CROP_HDR_30FPS},
	/* Add modes with no device tree support after below */
};
#endif /* __IMX185_I2C_TABLES__ */
