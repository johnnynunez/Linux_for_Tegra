/*
 * SPDX-FileCopyrightText: Copyright (c) 2020-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

#ifndef _DT_BINDINGS_GPIO_TEGRA234_GPIO_H
#define _DT_BINDINGS_GPIO_TEGRA234_GPIO_H

/* GPIOs implemented by main GPIO controller */
#define TEGRA234_MAIN_GPIO_PORT_A 0
#define TEGRA234_MAIN_GPIO_PORT_B 1
#define TEGRA234_MAIN_GPIO_PORT_C 2
#define TEGRA234_MAIN_GPIO_PORT_D 3
#define TEGRA234_MAIN_GPIO_PORT_E 4
#define TEGRA234_MAIN_GPIO_PORT_F 5
#define TEGRA234_MAIN_GPIO_PORT_G 6
#define TEGRA234_MAIN_GPIO_PORT_H 7
#define TEGRA234_MAIN_GPIO_PORT_I 8
#define TEGRA234_MAIN_GPIO_PORT_J 9
#define TEGRA234_MAIN_GPIO_PORT_K 10
#define TEGRA234_MAIN_GPIO_PORT_L 11
#define TEGRA234_MAIN_GPIO_PORT_M 12
#define TEGRA234_MAIN_GPIO_PORT_N 13
#define TEGRA234_MAIN_GPIO_PORT_P 14
#define TEGRA234_MAIN_GPIO_PORT_Q 15
#define TEGRA234_MAIN_GPIO_PORT_R 16
#define TEGRA234_MAIN_GPIO_PORT_X 17
#define TEGRA234_MAIN_GPIO_PORT_Y 18
#define TEGRA234_MAIN_GPIO_PORT_Z 19
#define TEGRA234_MAIN_GPIO_PORT_AC 20
#define TEGRA234_MAIN_GPIO_PORT_AD 21
#define TEGRA234_MAIN_GPIO_PORT_AE 22
#define TEGRA234_MAIN_GPIO_PORT_AF 23
#define TEGRA234_MAIN_GPIO_PORT_AG 24

#define TEGRA234_MAIN_GPIO(port, offset) \
		((TEGRA234_MAIN_GPIO_PORT_##port * 8) + offset)

/* GPIOs implemented by AON GPIO controller */
#define TEGRA234_AON_GPIO_PORT_AA 0
#define TEGRA234_AON_GPIO_PORT_BB 1
#define TEGRA234_AON_GPIO_PORT_CC 2
#define TEGRA234_AON_GPIO_PORT_DD 3
#define TEGRA234_AON_GPIO_PORT_EE 4
#define TEGRA234_AON_GPIO_PORT_GG 5

#define TEGRA234_AON_GPIO(port, offset) \
		((TEGRA234_AON_GPIO_PORT_##port * 8) + offset)

/* GPIOs implemented by FSI GPIO controller */
#define TEGRA234_FSI_GPIO_PORT_S 0
#define TEGRA234_FSI_GPIO_PORT_T 1
#define TEGRA234_FSI_GPIO_PORT_U 2
#define TEGRA234_FSI_GPIO_PORT_V 3
#define TEGRA234_FSI_GPIO_PORT_W 4

#define TEGRA234_FSI_GPIO(port, offset) \
		((TEGRA234_FSI_GPIO_PORT_##port * 8) + offset)

/* All pins */
#define TEGRA_PIN_BASE_ID_A 0
#define TEGRA_PIN_BASE_ID_B 1
#define TEGRA_PIN_BASE_ID_C 2
#define TEGRA_PIN_BASE_ID_D 3
#define TEGRA_PIN_BASE_ID_E 4
#define TEGRA_PIN_BASE_ID_F 5
#define TEGRA_PIN_BASE_ID_G 6
#define TEGRA_PIN_BASE_ID_H 7
#define TEGRA_PIN_BASE_ID_I 8
#define TEGRA_PIN_BASE_ID_J 9
#define TEGRA_PIN_BASE_ID_K 10
#define TEGRA_PIN_BASE_ID_L 11
#define TEGRA_PIN_BASE_ID_M 12
#define TEGRA_PIN_BASE_ID_N 13
#define TEGRA_PIN_BASE_ID_P 14
#define TEGRA_PIN_BASE_ID_Q 15
#define TEGRA_PIN_BASE_ID_R 16
#define TEGRA_PIN_BASE_ID_S 17
#define TEGRA_PIN_BASE_ID_T 18
#define TEGRA_PIN_BASE_ID_U 19
#define TEGRA_PIN_BASE_ID_V 20
#define TEGRA_PIN_BASE_ID_W 21
#define TEGRA_PIN_BASE_ID_X 22
#define TEGRA_PIN_BASE_ID_Y 23
#define TEGRA_PIN_BASE_ID_Z 24
#define TEGRA_PIN_BASE_ID_AA 25
#define TEGRA_PIN_BASE_ID_AC 26
#define TEGRA_PIN_BASE_ID_AD 27
#define TEGRA_PIN_BASE_ID_AE 28
#define TEGRA_PIN_BASE_ID_AF 29
#define TEGRA_PIN_BASE_ID_AG 30
#define TEGRA_PIN_BASE_ID_BB 31
#define TEGRA_PIN_BASE_ID_CC 32
#define TEGRA_PIN_BASE_ID_DD 33
#define TEGRA_PIN_BASE_ID_EE 34
#define TEGRA_PIN_BASE_ID_GG 35
#define TEGRA_PIN_BASE_ID_HH 36

#define TEGRA_PIN_BASE(port) (TEGRA_PIN_BASE_ID_##port * 8)

#define TEGRA234_MAIN_GPIO_RANGE(st, end) \
		((TEGRA234_MAIN_GPIO_PORT_##end - TEGRA234_MAIN_GPIO_PORT_##st + 1) * 8)
#define TEGRA234_MAIN_GPIO_BASE(port) (TEGRA234_MAIN_GPIO_PORT_##port * 8)

#define TEGRA234_AON_GPIO_RANGE(st, end) \
		((TEGRA234_AON_GPIO_PORT_##end - TEGRA234_AON_GPIO_PORT_##st + 1) * 8)
#define TEGRA234_AON_GPIO_BASE(port) (TEGRA234_AON_GPIO_PORT_##port * 8)
#define TEGRA234_FSI_GPIO_RANGE(st, end) \
		((TEGRA234_FSI_GPIO_PORT_##end - TEGRA234_FSI_GPIO_PORT_##st + 1) * 8)
#define TEGRA234_FSI_GPIO_BASE(port) (TEGRA234_FSI_GPIO_PORT_##port * 8)
#endif
