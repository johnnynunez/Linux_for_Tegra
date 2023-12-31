/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019-2023, NVIDIA CORPORATION.  All rights reserved.
 */

#ifndef DCE_LOG_H
#define DCE_LOG_H

struct tegra_dce;

enum dce_log_type {
	DCE_ERROR,
	DCE_WARNING,
	DCE_INFO,
	DCE_DEBUG,
};

/*
 * Each OS must implement these functions. They handle the OS specific nuances
 * of printing data to a UART, log, whatever.
 */
__printf(5, 6)
void dce_log_msg(struct tegra_dce *d, const char *func_name, int line,
			enum dce_log_type type, const char *fmt, ...);

/**
 * dce_err - Print an error
 *
 * @d        - Pointer to tegra_dce.
 * @fmt      - A format string (printf style).
 * @arg...   - Arguments for the format string.
 *
 * Uncondtionally print an error message.
 */
#define dce_err(d, fmt, arg...)					\
	dce_log_msg(d, __func__, __LINE__, DCE_ERROR, fmt, ##arg)

/**
 * dce_warn - Print a warning
 *
 * @d        - Pointer to tegra_dce.
 * @fmt      - A format string (printf style).
 * @arg...   - Arguments for the format string.
 *
 * Uncondtionally print a warming message.
 */
#define dce_warn(d, fmt, arg...)					\
	dce_log_msg(d, __func__, __LINE__, DCE_WARNING, fmt, ##arg)

/**
 * dce_info - Print an info message
 *
 * @d        - Pointer to tegra_dce.
 * @fmt      - A format string (printf style).
 * @arg...   - Arguments for the format string.
 *
 * Unconditionally print an information message.
 */
#define dce_info(d, fmt, arg...)					\
	dce_log_msg(d, __func__, __LINE__, DCE_INFO, fmt, ##arg)

/**
 * dce_debug - Print a debug message
 *
 * @d        - Pointer to tegra_dce.
 * @fmt      - A format string (printf style).
 * @arg...   - Arguments for the format string.
 *
 * print a debug message.
 */
#define dce_debug(d, fmt, arg...)					\
	dce_log_msg(d, __func__, __LINE__, DCE_DEBUG, fmt, ##arg)

#endif
