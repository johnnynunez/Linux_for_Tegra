#!/bin/bash

# SPDX-FileCopyrightText: Copyright (c) 2019-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
# This build script builds NVIDIA sources present in all source tar files
# present in this script's directory and it's sub-directories.
#

set -e

SCRIPT_NAME="$(basename "${0}")"
SCRIPT_ABS_PATH="$(readlink -f "${0}")"

export BSP_PATH="${BSP_PATH:-${SCRIPT_ABS_PATH%/source/public/${SCRIPT_NAME}}}"
export BUILD_DIR="${BUILD_DIR:-${BSP_PATH}/source/src_out}"

# shellcheck disable=SC2044,SC2185
for src_file in $(find -iname "*.tbz2") ; do
	export PKG_BUILD_DIR="${BUILD_DIR}/${src_file%.tbz2}_build"
	if tar -tvf "${src_file}" | grep "nvbuild.sh" ; then
		mkdir -p "${PKG_BUILD_DIR}"
		if [ ! -f "${PKG_BUILD_DIR}/nvbuild.sh" ]; then
			tar -xf "${src_file}" -C "${PKG_BUILD_DIR}"
			if [ "${src_file}" = "kernel_src.tbz2" ]; then
				# Extract kernel OOT modules source explicitly as this is not the part
				# of kernel and its compilation depends on the kernel build.
				if [ -f "kernel_oot_modules_src.tbz2" ]; then
					tar -xf kernel_oot_modules_src.tbz2  -C "${PKG_BUILD_DIR}"
				fi
				if [ -f "nvidia_kernel_display_driver_source.tbz2" ]; then
					tar -xf nvidia_kernel_display_driver_source.tbz2  \
						-C "${PKG_BUILD_DIR}"
				fi
			fi
		fi
		pushd "${PKG_BUILD_DIR}"
		./nvbuild.sh "${@}"
		popd
	else
		echo "nvbuild.sh not found for package ${src_file}"
		echo "Skipping ${src_file} build."
	fi
done
