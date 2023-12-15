#!/bin/bash

# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

#
# This build script builds the TOS image. The TOS image contains 3 binaries:
# 1. the OP-TEE image
# 2. the ATF image
# 3. the OP-TEE dtb
#

set -e

# shellcheck disable=SC2046
SCRIPT_DIR="$(dirname $(readlink -f "${0}"))"
SCRIPT_NAME="$(basename "${0}")"
SCRIPT_PREREQUISITE="nv_public_src_build.sh"

function usage {
        cat <<EOM
Usage: ./${SCRIPT_NAME} [OPTIONS]
This script builds the TOS image. This script must run after running ${SCRIPT_PREREQUISITE}.
It supports following options.
OPTIONS:
        -p                  Target platform. Possible values: t194|t234
        -u                  Specify the path of the UEFI stmm image.
        -s                  Specify the path of the script "gen_tos_part_img.py".
        -h                  Displays this help
EOM
}

TARGET_PLATFORM=""
UEFI_STMM=""
TOS_GEN_SCRIPT=""
while getopts "hp:u:s:" OPTION
do
	case ${OPTION} in
		p) TARGET_PLATFORM="${OPTARG}"; ;;
		u) UEFI_STMM="${OPTARG}"; ;;
		s) TOS_GEN_SCRIPT="${OPTARG}"; ;;
		h)
			usage
			exit 0
		;;
		*)
			usage
			exit 1
		;;
        esac
done

if [ "${TARGET_PLATFORM}" = "" ]; then
	echo "The platform value is missing. Use \"-p\" to set it."
	exit 1
fi
if [ "${TARGET_PLATFORM}" != "t194" ] && [ "${TARGET_PLATFORM}" != "t234" ]; then
	echo "The platform value is wrong. Supported platform values: t194|t234."
	exit 1
fi

if [ -z "${UEFI_STMM}" ]; then
	echo "The UEFI stmm image path is missing."
	exit 1
fi
if [ ! -f "${UEFI_STMM}" ]; then
	echo "Can't find the UEFI stmm image at: ${UEFI_STMM}"
	exit 1
fi

if [ -z "${TOS_GEN_SCRIPT}" ]; then
	echo "The gen_tos_part_img.py path is missing."
	exit 1
fi
if [ ! -f "${TOS_GEN_SCRIPT}" ]; then
	echo "Can't find gen_tos_part_img.py at: ${TOS_GEN_SCRIPT}"
	exit 1
fi
if [ ! -x "${TOS_GEN_SCRIPT}" ]; then
	echo "${TOS_GEN_SCRIPT} is not an executable program."
	exit 1
fi

if ! command -v dtc &> /dev/null
then
	echo "dtc could not be found."
	exit 1
fi

BUILD_DIR="${SCRIPT_DIR}/../src_out"
pushd "${BUILD_DIR}" >& /dev/null
# If ATF_BIN has been set, don't override
if [ -z "${ATF_BIN}" ]; then
	ATF_BIN="atf_src_build/arm-trusted-firmware/${NV_TARGET_BOARD}-${TARGET_PLATFORM}/tegra/${TARGET_PLATFORM}/release/bl31.bin"
fi
if [ ! -f "${ATF_BIN}" ]; then
	echo "Can't find the ATF image: ${BUILD_DIR}/${ATF_BIN}"
	echo "Did you run ${SCRIPT_PREREQUISITE}?"
	exit 1
fi

# Start to build OP-TEE
echo "Start to build OP-TEE..."
OPTEE_BUILD_DIR="optee_src_build"
rm -rf "${OPTEE_BUILD_DIR}"
mkdir -p "${OPTEE_BUILD_DIR}"
tar -xf "${SCRIPT_DIR}/nvidia-jetson-optee-source.tbz2" -C "${OPTEE_BUILD_DIR}"

export UEFI_STMM_PATH="${UEFI_STMM}"
pushd "${OPTEE_BUILD_DIR}" >& /dev/null
./optee_src_build.sh -p "${TARGET_PLATFORM}"
if [ "${TARGET_PLATFORM}" == "t194" ]; then
	dts_file="./optee/tegra194-optee.dts"
	dtb_file="./optee/tegra194-optee.dtb"
fi
if [ "${TARGET_PLATFORM}" == "t234" ]; then
	dts_file="./optee/tegra234-optee.dts"
	dtb_file="./optee/tegra234-optee.dtb"
fi
dtc -I dts -O dtb -o "${dtb_file}" "${dts_file}"
popd >& /dev/null

# Start to create the TOS image
echo "Start to create the TOS image..."
tee_bin="${OPTEE_BUILD_DIR}/optee/build/${TARGET_PLATFORM}/core/tee-raw.bin"
tos_img="tos-${TARGET_PLATFORM}.img"
rm -f "${tos_img}"
"${TOS_GEN_SCRIPT}" \
	--monitor "${ATF_BIN}" \
	--os "${tee_bin}" \
	--dtb "${OPTEE_BUILD_DIR}/${dtb_file}" \
	--tostype optee \
	./"${tos_img}"

if [ -f "${tos_img}" ]; then
	echo "The TOS image(${TARGET_PLATFORM}) has been created: ${BUILD_DIR}/${tos_img}"
fi

popd >& /dev/null
