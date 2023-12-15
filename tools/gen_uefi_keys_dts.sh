#!/bin/bash

# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.
#
# ****************************************************************
# Usage:
#	sudo ./gen_uefi_keys_dts.sh <uefi_keys.conf>
# ****************************************************************
#
# This script converts UEFI keys from either in .esl or in .auth form
# into the default UEFI security keys dts/dtbo or the update UEFI
# security keys dts/dtbo or both.
#
# User is expected to provide the .esl or .auth key config file in format
# as shown in below example <uefi_keys.conf>. The generated dts/dtbo with
# below names are stored in the same directory as the config file.
#
#    - UefiDefaultSecurityKeys.dts and UefiDefaultSecurityKeys.dtbo
#    - UefiUpdateSecurityKeys.dts and UefiUpdateSecurityKeys.dtbo
#
# An example <uefi_keys.conf>:
#
#   UEFI_DB_1_KEY_FILE="db_1.key";  # UEFI payload signing key
#   UEFI_DB_1_CERT_FILE="db_1.crt"; # UEFI payload signing key certificate
#
#   ## The default PK/KEK/DB/DBX key certificates in EFI Signature List(.esl)
#   UEFI_DEFAULT_PK_ESL="pk.esl"
#
#   UEFI_DEFAULT_KEK_ESL_0="kek_0.esl"
#   UEFI_DEFAULT_KEK_ESL_1="kek_1.esl"
#
#   UEFI_DEFAULT_DB_ESL_0="db_0.esl"
#   UEFI_DEFAULT_DB_ESL_1="db_1.esl"
#
#   UEFI_DEFAULT_DBX_ESL_0="dbx_0.esl"
#   UEFI_DEFAULT_DBX_ESL_1="dbx_1.esl"
#
#   ## The update KEK/DB/DBX keys certificates in signed esl (.auth)
#   UEFI_UPDATE_PRE_SIGNED_KEK_0="kek4update_0.auth"
#   UEFI_UPDATE_PRE_SIGNED_KEK_1="kek4update_1.auth"
#
#   UEFI_UPDATE_PRE_SIGNED_DBX_0="dbx4udpate_0.auth"
#   UEFI_UPDATE_PRE_SIGNED_DBX_1="dbx4update_1.auth"
#
#   UEFI_UPDATE_PRE_SIGNED_DB_0="db4update_0.auth"
#   UEFI_UPDATE_PRE_SIGNED_DB_1="db4update_1.auth"
#
# Notes:
#   1). All files specified in <uefi_keys.conf> must be in the same directory
#       of <uefi_keys.conf>.
#   2). UEFI_DB_1_KEY_FILE and UEFI_DB_1_CERT_FILE are used to sign kernel,
#       kernel-dtb, initrd, etc when UEFI key conf file is provided through
#       option --uefi-keys in flash.sh command line.
#   3). UEFI_DEFAULT_PK_ESL is PK esl file to initialize the PKDefault node
#       in dts, UEFI_DEFAULT_KEK_ESL_n is KEK esl file to initialize the
#       KEKDefault node in dts, UEFI_DEFAULT_DB_ESL_n is the db esl file to
#       initialize the dbDefault node in dts. UEFI_DEFAULT_DBX_ESL_n is the
#       dbx esl file to initialize the dbxDefault node in dts. User must
#       start setting from the UEFI_DEFAULT_KEK_ESL_0, UEFI_DEFAULT_DB_ESL_0
#       and UEFI_DEFAULT_DBX_ESL_0.
#   4). To generate UefiDefaultSecurityKeys.dtbo, user must specify one
#       UEFI_DEFAULT_PK_ESL, one or up to 3 UEFI_DEFAULT_KEK_ESL_n, and
#       UEFI_DEFAULT_DB_ESL_n. Specify UEFI_DEFAULT_DBX_ESL_n(up to 3) is optional.
#   5). To generate UefiUpdateSecurityKeys.dtbo, user needs to specify one or
#       up to 50 UEFI_UPDATE_PRE_SIGNED_KEK_n, UEFI_UPDATE_PRE_SIGNED_DBX_n
#       or UEFI_UPDATE_PRE_SIGNED_DB_n
#   6). The default keys and update keys can be provided through separate key
#       config files such as the default_uefi_keys.conf and update_uefi_keys.conf.
#       By doing so, the UefiDefaultSecurityKeys.dtbo and UefiUpdateSecurityKeys.dtbo
#       can be generated by using only corresponding key conf file. When update
#       keys are provided in separate key config file, make sure to add in
#       UEFI_DB_1_KEY_FILE and UEFI_DB_1_CERT_FILE. The key and cert may or may
#       not be the same as the ones provided in the default key config.
#   7). May need to install efitools.
#

DEFAULT_KEYS_DTS_FILE="UefiDefaultSecurityKeys.dts"
UPDATE_KEYS_DTS_FILE="UefiUpdateSecurityKeys.dts"

MAX_NUM_DEFAULT_PAYLOAD="3"
MAX_NUM_UPDATE_PAYLOAD="50"

OPTION_NO_SIGNING_KEY="--no-signing-key"

trap "catch_err" ERR

catch_err () {
	echo "gen_uefi_keys_dts.sh: error occurred !!!"
	exit 1
}

function usage () {
	echo "Usage: sudo ./gen_uefi_keys_dts.sh [${OPTION_NO_SIGNING_KEY}] <uefi_keys.conf>"
	echo ""
	echo "    Positional arguments:"
	echo "        <uefi_keys.conf>  Configuration file of UEFI keys."
	echo ""
	echo "    Optional arguments:"
	echo "        ${OPTION_NO_SIGNING_KEY}  Do not sign UEFI payload with"
	echo "                           the db key in <uefi_keys.conf>."
    exit 1
}

default_key_variables_spec=(
	# PKDefault variable
	'var_name=PKDefault;payload_name=UEFI_DEFAULT_PK_ESL'

	# KEKDefault variable
	'var_name=KEKDefault;payload_name=UEFI_DEFAULT_KEK_ESL'

	# dbDefault variable
	'var_name=dbDefault;payload_name=UEFI_DEFAULT_DB_ESL'

	# dbxDefault variable
	'var_name=dbxDefault;payload_name=UEFI_DEFAULT_DBX_ESL'
)

update_key_variables_spec=(
	# kekSigned_n variables
	'var_name=kekSigned;payload_name=UEFI_UPDATE_PRE_SIGNED_KEK'

	# dbSigned_n variables
	'var_name=dbSigned;payload_name=UEFI_UPDATE_PRE_SIGNED_DB'

	# dbxSigned_n variables
	'var_name=dbxSigned;payload_name=UEFI_UPDATE_PRE_SIGNED_DBX'
)

dts_header ()
{
	local dts_file="${1}"

	cat << EOF > "${dts_file}"
/** @file
*
*  Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
*
*  SPDX-License-Identifier: BSD-2-Clause-Patent
*
**/
/dts-v1/;
/plugin/;
/ {
    overlay-name = "UEFI Secure Boot Keys";
    fragment@0 {
        target-path = "/";
        board_config {
            sw-modules = "uefi";
        };
        __overlay__ {
            firmware {
                uefi {
                    variables {
                        gNVIDIAPublicVariableGuid {
                            EnrollDefaultSecurityKeys {
                                data = [01];
                                non-volatile;
                            };
EOF
}

global_variable_header ()
{
	local dts_file="${1}"

	cat << EOF >> "${dts_file}"
                        gEfiGlobalVariableGuid {
EOF
}

default_node_header ()
{
	local dts_file="${1}"
	local node_name="${2}"

	echo "Info: adding node ${node_name}."
	cat << EOF >> "${dts_file}"
                            ${node_name} {
                                data = [
EOF
}

default_node_tail ()
{
	local dts_file="${1}"

	cat << EOF >> "${dts_file}"
                                ];
                                non-volatile;
                            };
EOF
}

node_header ()
{
	local dts_file="${1}"
	local basename="${2}"
	local idx="${3}"
	local node_name="${basename}_${idx}"

	echo "Info: adding node ${node_name}."
	cat << EOF >> "${dts_file}"
                            ${node_name} {
                                data = [
EOF
}

node_tail ()
{
	local dts_file="${1}"

	cat << EOF >> "${dts_file}"
                                ];
                            };
EOF
}

dts_brace ()
{
	local dts_file="${1}"

	cat << EOF >> "${dts_file}"
                        };
EOF
}

dts_tail ()
{
	local dts_file="${1}"

	cat << EOF >> "${dts_file}"
                        };
                    };
                };
            };
        };
    };
};
EOF
}

check_and_get_number_of_files ()
{
	local base_file_name="${1}"
	local num="${2}"
	local max="${3}"
	local file_num=""

	for n in $(seq 0 $((max - 1))); do
		local file="${base_file_name}_${n}"
		if [ "${!file}" = "" ]; then
			continue
		elif [ ! -f "${!file}" ]; then
			echo "Error: ${file} does not exist."
			return 1
		fi
		file_num=$((file_num + 1))
	done

	# Return the number of found files
	eval "${num}=${file_num}"
}

convert_dts_to_dtbo ()
{
	local dts_file="${1}"
	local dts_file_base=""

	echo "Info: dts file is generated to" "${dts_file}"
	dts_file_base=$(basename "${dts_file%.*}")

	dtc -I dts -O dtb "${dts_file}" -o "${dts_file_base}.dtbo"
	echo "Info: dtbo file is generated to" "${dts_file_base}.dtbo"
}

generate_default_dts ()
{
	local dts_file="${1}"
	local cache_data=""
	local payload_file=""

	echo "Info: generating default keys dtbo."
	# PK, KEK and DB must be set for generating default keys dtbo.
	if [ "${UEFI_DEFAULT_PK_ESL}" = "" ] || [ ! -f "${UEFI_DEFAULT_PK_ESL}" ] \
		|| [ "${UEFI_DEFAULT_KEK_ESL_0}" = "" ] || [ ! -f "${UEFI_DEFAULT_KEK_ESL_0}" ] \
		|| [ "${UEFI_DEFAULT_DB_ESL_0}" = "" ] || [ ! -f "${UEFI_DEFAULT_DB_ESL_0}" ]; then
		# Clean up the dts file
		rm -vf "${dts_file}"
		echo "Info: no default key dtbo is generated due to no default keys are provided."
		return 0
	fi

	# Begin generating dts file
	dts_header "${dts_file}"
	dts_brace "${dts_file}"
	global_variable_header "${dts_file}"

	# Check the existence of payloads and append to dts.
	for spec in "${default_key_variables_spec[@]}";
	do
		eval "${spec}"

		# Process PKDefault
		if [ "${var_name}" = "PKDefault" ]; then
			cache_data=$(od -t x1 -An "${!payload_name}")
			# Write PKDefault
			default_node_header "${dts_file}" "${var_name}"
			echo "${cache_data}" >> "${dts_file}"
			default_node_tail "${dts_file}"
			continue
		fi

		# Process KEKDefault/dbDefault
		# Check the number and existence of input payloads
		if ! check_and_get_number_of_files "${payload_name}" "num_of_payload" \
			"${MAX_NUM_DEFAULT_PAYLOAD}"; then
			echo "Error: failed to check payload for ${var_name}."
			exit 1
		fi

		# Support input 3 sets payloads at most for KEKDefault/dbDefault.
		if [[ $((num_of_payload)) -gt $((MAX_NUM_DEFAULT_PAYLOAD)) ]]; then
			echo "Error: input ${num_of_payload} payloads for ${var_name}, exceed maximum(3)."
			exit 1
		fi

		# Append the payload to dts.
		cache_data=""
		for idx in $(seq 0 $((MAX_NUM_DEFAULT_PAYLOAD - 1))); do
			payload_file="${payload_name}_${idx}"
			if [ -f "${!payload_file}" ]; then
				cache_data+=$(od -t x1 -An "${!payload_file}")
			fi
		done

		if [ "${cache_data}" != "" ]; then
			# Write KEKDefault/dbDefault
			default_node_header "${dts_file}" "${var_name}"
			echo "${cache_data}" >> "${dts_file}"
			default_node_tail "${dts_file}"
		fi
	done

	# End of the dts file
	dts_tail "${dts_file}"

	convert_dts_to_dtbo "${dts_file}"
	echo "Info: ${dts_file} and corresponding dtbo are generated."
}

generate_update_dts ()
{
	local dts_file="${1}"
	local payload_file=""
	local data=""
	local total_num=""

	echo "Info: generating update keys dtbo."
	# Begin generating dts file
	dts_header "${dts_file}"

	# Check the existence of payloads and append to dts.
	for spec in "${update_key_variables_spec[@]}";
	do
		eval "${spec}"

		# Check the number and existence of input payloads
		if ! check_and_get_number_of_files "${payload_name}" "num_of_payload" \
			"${MAX_NUM_UPDATE_PAYLOAD}"; then
			echo "Error: failed to check payload for ${var_name}."
			exit 1
		fi

		# Support input 50 sets payloads at most.
		if [[ $((num_of_payload)) -gt $((MAX_NUM_UPDATE_PAYLOAD)) ]]; then
			echo "Error: input ${num_of_payload} payloads for ${var_name}, exceed maximum(50)."
			exit 1
		fi
		total_num=$((total_num + num_of_payload))

		# Append the payload to dts.
		local var_idx="0"
		for idx in $(seq 0 $((MAX_NUM_UPDATE_PAYLOAD - 1)));
		do
			payload_file="${payload_name}_${idx}"
			if [ -f "${!payload_file}" ]; then
				# Write kekSigned_n/dbSigned_n/dbxSigned_n to dts file
				node_header "${dts_file}" "${var_name}" "${var_idx}"
				data=$(od -t x1 -An "${!payload_file}")
				echo "${data}" >> "${dts_file}"
				node_tail "${dts_file}"
				var_idx=$((var_idx + 1))
			fi
		done
	done

	# kekSigned_n/dbSigned_n/dbxSigned_n are all not set
	if [[ $((total_num)) == 0 ]]; then
		# Clean up the dts file
		rm -vf "${dts_file}"
		echo "Info: no update key dtbo is generated due to no update keys are provided."
		return 0
	fi

	# End of the dts file
	dts_tail "${dts_file}"

	convert_dts_to_dtbo "${dts_file}"
	echo "Info: ${dts_file} and corresponding dtbo are generated."
}

function parse_options()
{
	local input_option=""

	if [ $# == 1 ]; then
		uefi_keys_conf="${1}"
	elif [ $# == 2 ]; then
		input_option="${1}"
		if [ "${input_option}" == "${OPTION_NO_SIGNING_KEY}" ]; then
			no_signing_key="1"
			uefi_keys_conf="${2}"
		else
			usage
		fi
	else
		usage
	fi

	if [ ! -f "${uefi_keys_conf}" ]; then
		echo "Error: UEFI key config file does not exist."
		usage
	fi
}

uefi_keys_conf=""
no_signing_key=""

parse_options "$@"

source "${uefi_keys_conf}"
# cd to ${uefi_keys_conf}'s directory
uefi_keys_conf_dir=$(dirname "${uefi_keys_conf}")
pushd "${uefi_keys_conf_dir}" > /dev/null 2>&1 || exit

# Check UEFI_DB_1_KEY_FILE and UEFI_DB_1_CERT_FILE
if [ "${no_signing_key}" != "1" ]; then
	if [ "${UEFI_DB_1_KEY_FILE}" = "" ] || [ "${UEFI_DB_1_CERT_FILE}" = "" ]; then
		echo "Error: UEFI_DB_1_KEY_FILE and UEFI_DB_1_CERT_FILE must be set."
		exit 1
	fi
	if [ ! -f "${UEFI_DB_1_KEY_FILE}" ]; then
		echo "Error: ${UEFI_DB_1_KEY_FILE} does not exist."
		exit 1
	fi
	if [ ! -f "${UEFI_DB_1_CERT_FILE}" ]; then
		echo "Error: ${UEFI_DB_1_CERT_FILE} does not exist."
		exit 1
	fi
fi

# Generate default key dtbo.
generate_default_dts "${DEFAULT_KEYS_DTS_FILE}"

# Generate update keys dtbo.
generate_update_dts "${UPDATE_KEYS_DTS_FILE}"

echo "Info: generating dtbo is done."

popd  > /dev/null 2>&1 || exit
exit 0
