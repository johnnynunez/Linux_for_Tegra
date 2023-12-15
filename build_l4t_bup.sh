#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2017-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

#
# Generate BL update payload (BUP) for Jetson platforms
#
# Usage:
#		build_l4t_bup.sh [options] <target_board> <root_device>
#
#		Where the output is file bl_update_payload under directory bootloader
#
#		Run build_l4t_bup.sh without any parameters to show usage and examples.
#

#
# build_l4t_bup.sh supports following options and two mandatory parameters:
#
#  --clean-up
#  --multi-spec
#  --single-image-bup <part name>
#  --bup-type <type>
#  -s <key_file>
#  <target_board>
#  <root_dev>
#
build_l4t_bup_usage ()
{
	me="${1}"
	state="${2}"
	retval="${3}"

	if [ "${state}" = "allunknown" ]; then
		echo -e "
Usage: [env={value},...] ${me} [options] <target_board> <rootdev>
Where,
    target board    target board name.
    rootdev         root device, mmcblk0p1

    --clean-up      Cleans up BUP buffer. Use this option to clean up BUP
                    buffer before starting to add in any images to BUP.
                    Default: Yes for non-multi-spec BUP, No for multi-spec BUP.
    --multi-spec    Indicates to create multi-spec BUP.
    --single-image-bup <part name>   Generate specified single image BUP.
    --bup-type <type>   Indicates the BUP type that can be either bl or kernel.
    -u <PKC key file>   Indicates the PKC key file used to sign images.
    -v <SBK key file>   Indicates Secure Boot Key (SBK) key used for ODM fused board.
    --user_key <key file>  User provided key file (16-byte) to encrypt user images,
                           like kernel, kernel-dtb and initrd.
                           If user_key is specified, SBK key (-v) has to be specified.

Examples:
    1. Build BUP for Jetson AGX Orin board connected to current host:
       Put board into forced recovery mode and then issue commaand:
        $ sudo ./build_l4t_bup.sh jetson-agx-orin-devkit mmcblk0p1

    2. Build BUP image completely offline by providing board id, fab # and
       fuse level through environment variables:
        $ sudo FAB=B00 BOARDID=3701 BOARDSKU=0000 FUSELEVEL=fuselevel_production \\
            ./build_l4t_bup.sh jetson-agx-orin-devkit mmcblk0p1

    3. Build multi-spec BUP image that can be used to update BLs for different
       FAB Jetson AGX Orin boards.
        # Clean BUP buffer
        $ sudo FAB=000 BOARDID=3701 BOARDSKU=0000 ./build_l4t_bup.sh --clean-up \\
               jetson-agx-orin-devkit mmcblk0p1
        # Build BUP for board spec 1, FAB=000
        $ sudo FAB=000 BOARDID=3701 BOARDSKU=0000 FUSELEVEL=fuselevel_production \\
            ./build_l4t_bup.sh --multi-spec jetson-agx-orin-devkit mmcblk0p1
        # Add in images for board spec 2, FAB C00
        $ sudo FAB=C00 BOARDID=3701 BOARDSKU=0000 FUSELEVEL=fuselevel_production \\
            ./build_l4t_bup.sh --multi-spec jetson-agx-orin-devkit mmcblk0p1

    4. Build PKC key signed images BUP:
        $ sudo FAB=B00 BOARDID=3701 BOARDSKU=0000 FUSELEVEL=fuselevel_production \\
            ./build_l4t_bup.sh -s <pkc_key_file> jetson-agx-orin-devkit mmcblk0p1
        Note: make sure <pkc_key_file> being already placed under current directory.

    5. Build single image BUP offline by providing board SPEC:
        $ sudo FAB=000 BOARDID=3701 BOARDSKU=0004 BOARDREV= FUSELEVEL=1 CHIPREV= \\
            ./build_l4t_bup.sh --single-image-bup A_xusb-fw jetson-agx-orin-devkit mmcblk0p1

    6. Build bootloader image BUP offline by providing board SPEC:
        $ sudo FAB=000 BOARDID=3767 BOARDSKU=0000 BOARDREV= FUSELEVEL=1 CHIPREV= \\
            ./build_l4t_bup.sh --bup-type bl jetson-agx-orin-devkit mmcblk0p1
	"; echo;
	fi
	exit "${retval}"
}

#
# build_l4t_bup.sh have at least two parameters
#
if [ $# -lt 2 ]; then
	build_l4t_bup_usage "${0}" "allunknown" 1
fi;

BUP_DIR=$(cd `dirname $0` && pwd)
"${BUP_DIR}/flash.sh" "--no-flash" "--bup" "${@}"
exit "${?}"
