#
# Copyright (c) 2018-2023, NVIDIA Corporation.  All Rights Reserved.
#
# NVIDIA Corporation and its licensors retain all intellectual property
# and proprietary rights in and to this software, related documentation
# and any modifications thereto.  Any use, reproduction, disclosure or
# distribution of this software and related documentation without an express
# license agreement from NVIDIA Corporation is strictly prohibited.
#
from tegrasign_v3_util import *
import hashlib

'''
@Description
The purpose of this file is to supply a list of API hooks and reference implementations
that may be useful for running with an HSM server.
As such, the API hooks are identified as required, and will be denoted with [REQUIRE]
tag below in the individual comment's @note section, whereas reference implementations
will be denoted as [REFERENCE].

@Rationale
The API hooks are required because they are used in the tegrasign_v3 scripts and OEMs
can optionally replace with their implementation. This decision is purely based on OEMs.
The reference implementations are used in the API hooks to mimic HSM operations, but
how the actual HSM servers will handle such the operations are HSM-specific.

@Note
The API hooks are secure boot operation related, yet not all are required for an OEM to
overwrite. The actual list is dependent on which secure boot scheme is chosen by the OEM.

Below is a list of API hooks in this file:
    do_hmac_sha256_hsm
    do_random_hsm
    do_aes_gcm_hsm
    do_rsa_pss_hsm
    do_ed25519_hsm
    get_rsa_mod_hsm
    get_rsa_mod_from_pubkey_hsm
    get_rsa_mont_hsm
    get_rsa_mont_from_pubkey_hsm
    get_ed25519_pub_hsm
    oem_hsm_kdf
    oem_hsm_aes_gcm
    oem_hsm_hmacsha

Below is a list of reference implementations in this file:
    get_key_file_hsm
    get_sbk_key_content
    hsm_server_store_derived_key_to_key_database
    hsm_server_search_key_database
    nist_sp800_108_kdf
    get_fskpkey_hsm_server
    get_sbk_hsm_server
    send_to_hsm_server_kdf
    hsm_server_aes_gcm
    send_to_hsm_server_aes_gcm
    send_to_hsm_server_hmacsha

Below is a simple partial breakdown for clarity:

hsm.py        -->  HSM/some secure host       -->  HSM server
(API hook)         (Reference API)                 (Reference API)
==============     ===========================     =================================================
oem_hsm_kdf()      send_to_hsm_server_kdf()        hsm_server_search_key_database() + key derivation
oem_hsm_aes_gc()   send_to_hsm_server_aes_gcm()    hsm_server_search_key_database() + encryption
oem_hsm_hmacsh()   send_to_hsm_server_hmacsha()    hsm_server_search_key_database() + hmac-sha

'''

# This is a configuration file that defines NV debug keys
NV_DEBUG_YAML = 'tegrasign_v3_debug.yaml'

'''
@brief The routine that maps the key file to key type
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] p_key SignKey class which has info needed: filename, type
@Note: There are three ways to mimic HSM code path:
1) use tegrasign_v3_debug.yaml, which is NV approach to mimic HSM behavior.
   The file format is of the following:
    {"HSM":
        {
            "SBK_KEY"     : "/media/automotive/sbk_hsm.key",
            "KEK0_KEY"    : "/media/automotive/kek0_hsm.key",
            "FSKP_AK_KEY" : "/media/automotive/fskp_ak_hsm.key",
            "FSKP_EK_KEY" : "/media/automotive/fskp_ek_hsm.key",
            "FSKP_KDK_KEY": "/media/automotive/fskp_kdk_hsm.key",
            "FSKP_KEY"    : "/media/automotive/fskp_hsm.key",
            "PKC_KEY"     : "/media/automotive/pkc_hsm.key",
            "PKC_PUBKEY"  : "/media/automotive/pkc_hsm.pubkey",
            "ED25519_KEY" : "/media/automotive/ed25519_hsm.key"
        }
    }
2) specify key path via --key <file_name>
3) ovewrite p_key.filename = p_key.filename in the following routine

@retval key file path
'''
def get_key_file_hsm(p_key, is_priv_key=True):
    if (p_key.hsm.is_algo_only()):
        info_print('[HSM] Using defined key: ' + p_key.filename)
        return p_key.filename

    key_type = p_key.hsm.get_type()
    info_print('[HSM] key type ' + key_type)

    # First check if the file is 'None', if so no need to modify
    if (p_key.filename == 'None'):
        info_print('[HSM] Loading zero sbk key ')
        return p_key.filename

    # Next check if NV debug file is present
    yaml_path = search_file(NV_DEBUG_YAML)
    if os.path.isfile(yaml_path):
        try:
            info_print('[HSM] Found ' + yaml_path)
            import yaml
            with open(yaml_path) as f:
                params = yaml.safe_load(f)
                if (key_type == KeyType.SBK):
                    p_key.filename = params['HSM']['SBK_KEY']
                elif (key_type == KeyType.KEK0):
                    p_key.filename = params['HSM']['KEK0_KEY']
                elif (key_type == KeyType.FSKP_AK):
                    p_key.filename = params['HSM']['FSKP_AK_KEY']
                elif (key_type == KeyType.FSKP_EK):
                    p_key.filename = params['HSM']['FSKP_EK_KEY']
                elif (key_type == KeyType.FSKP_KDK):
                    p_key.filename = params['HSM']['FSKP_KDK_KEY']
                elif (key_type == KeyType.FSKP):
                    p_key.filename = params['HSM']['FSKP_KEY']
                elif (key_type == KeyType.PKC):
                    if is_priv_key:
                        p_key.filename = params['HSM']['PKC_KEY']
                    else:
                        p_key.filename = params['HSM']['PKC_PUBKEY']
                elif (key_type == KeyType.ED25519):
                    p_key.filename = params['HSM']['ED25519_KEY']
            info_print('[HSM] Loading NVIDIA debug key: ' + str(p_key.filename))
        except Exception as e:
            raise tegrasign_exception('Please check file content for ' + key_type + ' define in ' + NV_DEBUG_YAML)
    else:
        if (key_type == KeyType.SBK):
            p_key.filename = p_key.filename
        elif (key_type == KeyType.KEK0):
            p_key.filename = p_key.filename
        elif (key_type == KeyType.FSKP_AK):
            p_key.filename = p_key.filename
        elif (key_type == KeyType.FSKP_EK):
            p_key.filename = p_key.filename
        elif (key_type == KeyType.FSKP_KDK):
            p_key.filename = p_key.filename
        elif (key_type == KeyType.FSKP):
            p_key.filename = p_key.filename
        elif (key_type == KeyType.PKC):
            if is_priv_key:
                p_key.filename = p_key.filename
            else:
                p_key.filename = p_key.filename
        elif (key_type == KeyType.ED25519):
            p_key.filename = p_key.filename
        info_print('[HSM] Loading HSM key: ' + str(p_key.filename))
    if (p_key.filename == None):
        raise tegrasign_exception('[HSM] ERROR: ' + key_type
            + ' does not have key path specified. Please either specify --key <filename>, or define in get_key_file_hsm(), or in '
            +  NV_DEBUG_YAML)

'''
@brief The routine that reads the sbk/kek0/fskp key content
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] key_file The file to be read

@retval key The buffer that is read in string format
'''
def get_sbk_key_content(p_key):
    key_file = p_key.filename
    key_type = p_key.hsm.get_type()
    if key_file == 'None':
        return hex_to_str(p_key.key.aeskey)
    else:
        with open_file(key_file, 'rb') as f:
            key_ = f.read()
            if key_[:2] == b'0x':
                # The key below is just concatenation of hex literals in the key file
                # key format is printable 0x123456578 0x9abcdef0 ...
                key = key_.decode().strip().replace('0x', '').replace(' ', '')
            else:
                try:
                    key_dec = key_.decode().strip()

                    if (len(key_dec) == 32) or (len(key_dec) == 64):
                        # assume key format is ascii
                        key = key_dec
                    else:
                        # key format is in a binary sequence
                        key = binascii.hexlify(key_).decode('ascii')
                except UnicodeDecodeError:
                    # key format is in a binary sequence
                    key = binascii.hexlify(key_).decode('ascii')
            return key
    raise tegrasign_exception("[HSM] ERROR: can not extract key content for %s" % (key_file))

'''
@brief The routine that invokes hmacsha on the buffer
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] buf Buffer to be operated on
@param[in] p_key SignKey class which has info needed: filename, mode

@param[in] use_der_key Boolean flag indicating if reading the key from the file path defined for HSM,
           or use the key value from SignKey
           The true flag indicates taking the key value from the SignKey as this value is previously
           derived from an operation
           The false flag indicates reading the key from the file path defined for HSM operation

@retval hmac The buffer after operation
'''
def do_hmac_sha256_hsm(buf, p_key, use_der_key = False):
    tmpf_in = 'tmp_hmacsha.in'
    tmpf_out = 'tmp_hmacsha.mac'

    with open_file(tmpf_in, 'wb') as f:
        write_file(f, buf)

    if (use_der_key == True):
        key = hex_to_str(p_key.key.aeskey)
    else:
        key_type = p_key.hsm.get_type()
        get_key_file_hsm(p_key)
        key = get_sbk_key_content(p_key)

    runcmd = 'openssl dgst -sha256 -mac hmac -macopt hexkey:%s -binary -out %s %s' % (key, tmpf_out, tmpf_in)
    info_print('[HSM] calling %s' % runcmd)
    try:
        subprocess.check_call(runcmd, shell=True)
    except subprocess.CalledProcessError:
        info_print("[HSM] ERROR: failure in running %s" % runcmd)
        exit_routine()
    finally:
        os.remove(tmpf_in)

    with open_file(tmpf_out, 'rb') as f:
        hmac = f.read()

    os.remove(tmpf_out)

    info_print('[HSM] hmacsha256 is done... return')

    return hmac

'''
@brief The routine that invokes random string generation
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] p_key SignKey class which has info needed: ran.size, ran.count
@note
   size = byte size of the random string
   count = number of random strings to be generated

@param[out] p_key.ran.buf This holds the random hex arrays of ran.size length by ran.count:

@retval None
'''
def do_random_hsm(p_key):
    info_print('[HSM] Generating random strings: %d x %d ' %(p_key.ran.size, p_key.ran.count))
    p_key.ran.buf = bytearray(p_key.ran.size * p_key.ran.count)

    for i in range(p_key.ran.count):
        buf = random_gen(p_key.ran.size)
        start = i * p_key.ran.size
        p_key.ran.buf[start:start+p_key.ran.size] = buf[:]

    info_print('[HSM] Generated random strings: %s ' %(hex_to_str(p_key.ran.buf)))

'''
@brief The routine that invokes aes-gcm on the buffer
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] buf Buffer to be operated on
@param[in] p_key SignKey class which has info needed: filename, mode, iv, aad, tag, verify
@note
   iv field is expected to be the random value
   tag field should be filled with the generated value
   verify  This is for verifying.
           If set to 0 means to encrypt, if set to a filename means to decrypt, where the buf
           is the encrypted buffer, and the filename is the original source

@param[in] use_der_key Boolean flag indicating if reading the key from the file path defined for HSM,
           or use the key value from SignKey
           The true flag indicates taking the key value from the SignKey as this value is previously
           derived from an operation
           The false flag indicates reading the key from the file path defined for HSM operation

@retval buf_enc The buffer after operation
'''
def do_aes_gcm_hsm(buf, p_key, use_der_key = False):
    if (use_der_key == True):
        key_str = hex_to_str(p_key.key.aeskey)
    else:
        key_type = p_key.hsm.get_type()
        get_key_file_hsm(p_key)
        key_str = get_sbk_key_content(p_key)

    iv  = p_key.kdf.iv.get_hexbuf()
    aad  = p_key.kdf.aad.get_hexbuf()
    tag  = p_key.kdf.tag.get_hexbuf()

    if (type(p_key.kdf.verify) == int):
        verify_bytes = p_key.kdf.verify
    else:
        verify_bytes = len(p_key.kdf.verify) + 1

    base_name = script_dir + 'v3_gcm_' + pid
    raw_name = base_name + '.raw'
    result_name = base_name + '.out'
    # check tag and verify_file are both defined
    if (type(tag) == int and type(p_key.kdf.verify) == str):
        raise tegrasign_exception('--tag and --verify must both be specified')

    raw_file = open_file(raw_name, 'wb')

    key_bytes = len(key_str)/2
    keysize_bytes = int_2byte_cnt(key_bytes)
    len_bytes = int_2byte_cnt(p_key.len)
    enc_bytes = len(buf)
    dest_bytes = int(p_key.len)
    result_bytes = len(result_name) + 1
    if (type(iv) == type(None)):
        iv_bytes = 0
    else:
        iv_bytes = len(binascii.hexlify(iv))/2
    if (type(aad) == type(None)):
        aad_bytes = 0
    else:
        aad_bytes = len(binascii.hexlify(aad))/2

    if (type(tag) == type(None)):
        tag_bytes = 0
    else:
        tag_bytes = len(binascii.hexlify(tag))/2

    buff_dest = "0" * dest_bytes

    # to write to file in the following order:
    # sizes for: key, keysize, length, buf, buff_dest, result_name, iv, aad, tag, verify,
    # data of: key, key size, length, buffer, buff_dest, result_name, iv, add, tag, verify
    # Note: verify, if non-zero in length, is the original file to be verified against,
    #       so buf will be the encrypted content

    num_list = [key_bytes, keysize_bytes, len_bytes, enc_bytes, dest_bytes, result_bytes, iv_bytes, aad_bytes, tag_bytes, verify_bytes]
    for num in num_list:
        arr = int_2bytes(4, num)
        write_file(raw_file, arr)

    write_file(raw_file, str_to_hex(key_str))
    arr = int_2bytes(keysize_bytes, key_bytes)
    write_file(raw_file, arr)
    arr = int_2bytes(len_bytes, p_key.len)
    write_file(raw_file, arr)
    write_file(raw_file, bytes(buf))
    write_file(raw_file, buff_dest.encode("utf-8"))
    write_file(raw_file, result_name.encode("utf-8"))
    nullarr = bytearray(1)
    nullarr[0] = 0          # need this null for char*
    write_file(raw_file, nullarr)
    if iv_bytes > 0:
        write_file(raw_file, iv)
    if aad_bytes > 0:
        write_file(raw_file, aad)
    if tag_bytes > 0:
        write_file(raw_file, tag)
    if verify_bytes > 0:
        write_file(raw_file, p_key.kdf.verify.encode("utf-8"))
        nullarr = bytearray(1)
        nullarr[0] = 0          # need this null for char*
    raw_file.close()

    command = exec_file(TegraOpenssl)
    command.extend(['--aesgcm', raw_name])
    command.extend(['--verbose'])

    ret_str = run_command(command)
    if (isinstance(tag, int) == False) and (type(p_key.kdf.verify) == str):
        info_print ('********* Verification complete. Quitting. *********')
        sys.exit(1)

    else:
        if check_file(result_name):
            result_fh = open_file(result_name, 'rb')
            buff_sig = result_fh.read() # Return data to caller
            result_fh.close()
            os.remove(result_name)
        start = ret_str.find('tag')
        tag_str_len = 4
        if (start > 0):
            if tag_bytes > 0:
                end = start + tag_str_len + int(tag_bytes * 2)
            else:
                end = len(ret_str)
            p_key.kdf.tag.set_buf(str_to_hex(ret_str[start+tag_str_len:end]))
    os.remove(raw_name)
    return buff_sig

'''
@brief The routine that invokes rsa-pss on the buffer
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] buf Buffer to be operated on
@param[in] p_key SignKey class which has info needed: filename, sha mode

@retval sig_data The buffer after operation
'''
def do_rsa_pss_hsm(buf, p_key):

    sha_str = 'sha256' if (p_key.key.pkckey.Sha ==  Sha._256) else 'sha512'
    tmpf_in = 'tmp_rsa_pss.in'
    tmpf_out = 'tmp_rsa_pss.sig'
    tmpf_hash = 'tmp_%s.hash' % (sha_str)

    get_key_file_hsm(p_key)
    priv_keyf = p_key.filename

    with open_file(tmpf_in, 'wb') as f:
        write_file(f, buf)

    # rsa_pss_saltlen:-1 means the same length of hash (sha256|sha512) here
    # single line execution for sha256:
    # runcmd = "openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sign %s -out %s %s" % (priv_keyf, tmpf_out, tmpf_in)

    # two separate line execution with intermediate sha256|sha512 output
    runcmd1 = "openssl dgst -%s -binary -out %s %s" % (sha_str, tmpf_hash, tmpf_in)
    runcmd2 = "openssl pkeyutl -sign -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:%s -in %s -out %s -inkey %s" % (sha_str, tmpf_hash, tmpf_out, priv_keyf)
    info_print('[HSM] calling %s\n[HSM] %s' % (runcmd1, runcmd2))
    try:
        subprocess.check_call(runcmd1, shell=True)
        subprocess.check_call(runcmd2, shell=True)
    except subprocess.CalledProcessError:
        print("[HSM] ERROR: failure in running %s, %s" % (runcmd1, runcmd2))
        exit_routine()
    finally:
        os.remove(tmpf_in)

    with open_file(tmpf_out, 'rb') as f:
        sig_data = swapbytes(bytearray(f.read()))

    os.remove(tmpf_hash)
    os.remove(tmpf_out)

    info_print('[HSM] rsa-pss routine is done... return')

    return sig_data

'''
@brief The routine that invokes ed25519 on the buffer
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] buf Buffer to be operated on
@param[in] p_key SignKey class which has info needed: filename

@retval sig_data The buffer after operation
'''
def do_ed25519_hsm(buf, p_key):

    buff_sig = "0" * p_key.keysize
    length = len(buf)

    current_dir_path = os.path.dirname(os.path.realpath(__file__))
    raw_name = current_dir_path + '/ed_raw.bin'
    result_name = current_dir_path + '/ed_out.bin'
    raw_file = open_file(raw_name, 'wb')

    get_key_file_hsm(p_key)
    filename_bytes = len(p_key.filename) + 1 # to account for 0x0
    len_bytes = int_2byte_cnt(length)
    sign_bytes = len(buf)
    sig_bytes = len(buff_sig)
    pkh_bytes = 0
    result_bytes = len(result_name) + 1

    # order: sizes then data for: file name, length, buff_to_sign, buff_sig, pkhfile, result_name
    arr = int_2bytes(4, filename_bytes)
    write_file(raw_file, arr)
    arr = int_2bytes(4, len_bytes)
    write_file(raw_file, arr)
    arr = int_2bytes(4, sign_bytes)
    write_file(raw_file, arr)
    arr = int_2bytes(4, sig_bytes)
    write_file(raw_file, arr)

    arr = int_2bytes(4, pkh_bytes)
    write_file(raw_file, arr)
    arr = int_2bytes(4, result_bytes)
    write_file(raw_file, arr)

    write_file(raw_file, bytes(p_key.filename.encode("utf-8")))
    nullarr = bytearray(1)
    nullarr[0] = 0          # need this null for char*
    write_file(raw_file, nullarr)

    arr = int_2bytes(len_bytes, length)
    write_file(raw_file, arr)

    write_file(raw_file, buf)
    write_file(raw_file, bytes(buff_sig.encode("utf-8")))

    if (pkh_bytes > 0):
        write_file(raw_file, bytes(pkhfile.encode("utf-8")))
        write_file(raw_file, nullarr)

    write_file(raw_file, bytes(result_name.encode("utf-8")))
    write_file(raw_file, nullarr)

    raw_file.close()

    command = exec_file(TegraOpenssl)
    command.extend(['--ed25519', raw_name])

    ret_str = run_command(command)

    if check_file(result_name):
        result_fh = open_file(result_name, 'rb')
        buff_sig = result_fh.read()
        result_fh.close()
        os.remove(result_name)

    os.remove(raw_name)
    return buff_sig

'''
@brief The routine that generates the public modulus for the RSA private key
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] p_key SignKey class which has info needed: filename, and keysize is updated
@param[in] pub_modf RSA public key filename

@retval True for success, False otherwise
'''
def get_rsa_mod_hsm(p_key, pub_modf=None):

    get_key_file_hsm(p_key)
    runcmd = 'openssl rsa -in %s -modulus -noout' % (p_key.filename)
    info_print('[HSM] calling %s' % runcmd)
    try:
        output = subprocess.check_output(runcmd, shell=True).decode("utf-8")
    except subprocess.CalledProcessError:
        info_print("[HSM] ERROR: failure in running %s" % runcmd)
        info_print('[HSM] Done - get_rsa_modulus_hsm. Key is not RSA key')
        return False
    # Check if the output is 'Modulus=963E...'
    if not output.startswith('Modulus='):
        info_print('[HSM] Done - get_rsa_modulus_hsm. Key is not RSA key')
        return False

    rsa_n_bin = swapbytes(bytearray(binascii.unhexlify(output.strip()[len('Modulus='):])))
    p_key.keysize = len(rsa_n_bin)

    success = (p_key.keysize != 0) # Assuming modulus has valid input
    if pub_modf:
        with open_file(pub_modf, 'wb') as f:
            write_file(f, rsa_n_bin)
    info_print('[HSM] Done - get_rsa_modulus_hsm. Key is' + (' RSA key ' if (success == True) else ' not RSA key'))

    return success

'''
@brief The routine that generates the Montgomery values from the RSA key passed in
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] p_key SignKey class which has info needed: filename, and keysize is updated
@param[in] pub_montf RSA Montgomery filename

@retval True for success, False otherwise
'''
def get_rsa_mont_hsm(p_key, pub_montf):

    get_key_file_hsm(p_key)
    pub_modf = p_key.filename + '_public'

    command = exec_file(TegraOpenssl)
    command.extend(['--isPkcKey', p_key.filename, pub_modf, pub_montf])
    ret_str = run_command(command)

    os.remove(pub_modf)
    success = False

    # scan the return string for decimal value
    m = re.search('Key size is (\d+)', ret_str)
    if m:
        keysize = int(m.group(1))
        if (keysize > 0 ) and (keysize < NV_RSA_MAX_KEY_SIZE):
            success = True
    info_print('[HSM] Done - get_rsa_mont_hsm. Montgomery values' + (' successful ' if (success == True) else ' failed'))

    return success

'''
@brief The routine that generates the public modulus for the RSA public key
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] p_key SignKey class which has info needed: filename, and keysize is updated
@param[in] pub_modf RSA public key filename

@retval True for success, False otherwise
'''
def get_rsa_mod_from_pubkey_hsm(p_key, pub_modf=None):

    is_priv_key = False
    get_key_file_hsm(p_key, is_priv_key)
    runcmd = 'openssl rsa -pubin -inform PEM -noout  -in %s -modulus ' % (p_key.filename)
    info_print('[HSM] calling %s' % runcmd)
    try:
        output = subprocess.check_output(runcmd, shell=True).decode("utf-8")
    except subprocess.CalledProcessError:
        info_print("[HSM] ERROR: failure in running %s" % runcmd)
        info_print('[HSM] Done - get_rsa_mod_from_pubkey_hsm. Key is not RSA public key')
        return False
    # Check if the output is 'Modulus=963E...'
    if not output.startswith('Modulus='):
        info_print('[HSM] Done - get_rsa_mod_from_pubkey_hsm. Key is not RSA public key')
        return False

    rsa_n_bin = swapbytes(bytearray(binascii.unhexlify(output.strip()[len('Modulus='):])))
    p_key.keysize = len(rsa_n_bin)

    success = (p_key.keysize != 0) # Assuming modulus has valid input
    if pub_modf:
        with open_file(pub_modf, 'wb') as f:
            write_file(f, rsa_n_bin)
    info_print('[HSM] Done - get_rsa_mod_from_pubkey_hsm. Key is' + (' RSA key ' if (success == True) else ' not RSA key'))

    return success

'''
@brief The routine that generates the Montgomery values from the RSA public key passed in
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] p_key SignKey class which has info needed: filename, and keysize is updated
@param[in] pub_montf RSA Montgomery filename

@retval True for success, False otherwise
'''
def get_rsa_mont_from_pubkey_hsm(p_key, pub_montf):

    is_priv_key = False
    get_key_file_hsm(p_key, is_priv_key)
    pub_modf = p_key.filename + '_public'

    command = exec_file(TegraOpenssl)
    command.extend(['--isPkcPubKey', p_key.filename, pub_modf, pub_montf])
    ret_str = run_command(command)

    os.remove(pub_modf)
    success = False

    # scan the return string for decimal value
    m = re.search('Key size is (\d+)', ret_str)
    if m:
        keysize = int(m.group(1))
        if (keysize > 0 ) and (keysize < NV_RSA_MAX_KEY_SIZE):
            success = True
    info_print('[HSM] Done - get_rsa_mont_hsm. Montgomery values' + (' successful ' if (success == True) else ' failed'))

    return success

'''
@brief The routine that generates the public key for the ED25519 key passed in
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] p_key SignKey class which has info needed: filename, and keysize is updated
@param[in] pub_keyf ED25519 public key filename

@retval True for success, False otherwise
'''
def get_ed25519_pub_hsm(p_key, pub_keyf):

    get_key_file_hsm(p_key)
    command = exec_file(TegraOpenssl)

    if pub_keyf == None:
        command.extend(['--isEd25519Key', p_key.filename])
    else:
        command.extend(['--isEd25519Key', p_key.filename, pub_keyf])

    success = False
    ret_str = run_command(command)
    if is_ret_ok(ret_str):
        p_key.keysize = ED25519_SIG_SIZE
        success = True

    info_print('[HSM] Done - get_ed25519_pub_hsm. Key is' + (' ED25519 key ' if (success == True) else ' not ED25519 key'))

    return success

'''
@brief The routine stores the [key, value] in the database
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] output_key_id The key to be stored in the database
@param[in] output_key_val The matching key value to be stored in the database

@retval True for success, False otherwise
'''
def hsm_server_store_derived_key_to_key_database(output_key_id, output_key_val):
    try:
        with open(TegraSign_v3_Keystore, 'a+') as f:
            content = f.read()
            if output_key_id in content:
                info_print('[HSM] %s is found in the database' %(output_key_id))
                return True
            info_print('[HSM] database writing: %s %s\n' %(output_key_id, hex_to_str(output_key_val)))
            f.write('%s %s\n' %(output_key_id, hex_to_str(output_key_val)))
        return True
    except Exception as e:
        info_print('[HSM] Error in database writing %s: %s\n' %(output_key_id, str(e)))
        return False

'''
@brief The routine searches through database for the requesting key
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] in_key_id The key requests in the database

@retval in_key for success, None for not found
'''
def hsm_server_search_key_database(in_key_id):
    in_key = None

    if os.path.exists(TegraSign_v3_Keystore) == False:
        return in_key

    with open(TegraSign_v3_Keystore, 'r') as f:
        content = f.read()

        index = content.find(in_key_id)
        if index != -1:
            end = content.find('\n', index)
            in_key = content[index + len(in_key_id) + 1: end]
    info_print('[HSM] database search: %s = %s\n' %(in_key_id, str(in_key)))
    return in_key

'''
@brief The routine implement NIST SP800 108 KDF in counter mode with
# counter encoded as little-endian 32 bit counter
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] input_kdf_key The key value to be operated on
@param[in] in_label Label for the key
@param[in] in_context Context for the key

@retval output_key The finished value
'''
def nist_sp800_108_kdf(input_kdf_key, in_label, in_context):

    HexLabel = True
    HexContext = True
    msgStr = get_composed_msg(in_label, in_context, 256, HexLabel, HexContext)
    msg = str_to_hex(msgStr)

    backup = SignKey()
    backup.key.aeskey = str_to_hex(input_kdf_key)

    backup.keysize = len(backup.key.aeskey)
    output_key = do_hmac_sha256_hsm(msg, backup, True)

    return output_key

'''
@brief The routine obtains FSKP related key string from the HSM server
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] key_type The key type options are: FSKP_KDK, FSKP_EK, FSKP_AK

@retval fskp key in string format
'''
def get_fskpkey_hsm_server(key_type):
    p_key = SignKey()
    p_key.hsm.type = key_type

    get_key_file_hsm(p_key)
    return get_sbk_key_content(p_key)

'''
@brief The routine obtains SBK key string from the HSM server
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@retval SBK key in string format
'''
def get_sbk_hsm_server():
    p_key = SignKey()
    p_key.hsm.type = KeyType.SBK

    get_key_file_hsm(p_key)
    return get_sbk_key_content(p_key)

'''
@brief The routine requests HSM server to search the key_id in the database
 If it is not found, then HSM server should perform kdf derivation
 and store the [key, value] pair in its database
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] in_key_id A string key ID and is to be used as input key for the KDF.
                     Type: string in ASCII.
                     Example: "SBK", "SBK_BCT_KDK_71f920fa275127a7b60fa4d4d41432a3"

@param[in] in_label The derivation label, to be used as input for the KDF.
                    Type: string of hex bytes.
                    Example: "00000000000000000000000000000000"

@param[in] in_context The derivation context, to be used as input for the KDF.
                      Type: string of hex bytes.
                      Example: "01010000", can be empty - ""

@param[in] output_key_id The string key ID of newly derived and stored inside OEM HSM key.
                         Type: string in ASCII.
                         Example: "SBK_BCT_DK_43c191bf6d6c3f263a8cd0efd4a058ab"
               About producing the output_key_id below:
               case 1) for in_key_id = SBK, FSKP_KDK, FSKP_EK, FSKP_AK, the stored value is fetched
               Note: due to the nature of the key, thus for FSKP_EK, FSKP_AK,
                     no further derivation is needed, while SBK and FSKP_KDK are
                     used for further derivation
               case 2) for other cases, derivation of in_key_id is performed

@retval True for success, False otherwise
'''
def send_to_hsm_server_kdf(in_key_id, in_label, in_context, output_key_id):
    found_cached_key_id = hsm_server_search_key_database(output_key_id)

    # if derived key found then return success
    if found_cached_key_id != None:
        return True

    # SBK - special case - it's imported/generated in OEM
    if in_key_id == "SBK":
        input_kdf_key = get_sbk_hsm_server() # load secret SBK root key in the HSM
        info_print('[HSM] Setting SBK value = ' + input_kdf_key)

    # Note: If --hsm fskp_kdk is specified, then we search the database for the derived
    # fskp_ek and fskp_ak entries, and creat them if not found. They are defined as:
    #fskp_ek_md5um(fskp_ek_<label>_) or fskp_ak_md5um(fskp_ak_<label>_)
    # Below is a mock up behavior to be implemented by OEMs based on their use case
    elif in_key_id == "FSKP_KDK":
        input_kdf_key = get_fskpkey_hsm_server(in_key_id) # load secret FSKP key in the HSM
        info_print('[HSM] Setting FSKP_KDK value = ' + input_kdf_key)

    # If --hsm fskp_ek or --hsm fskp_ak is specified, then the matching entry is searched
    # first with the above naming style. Or if the entries are not found, then we default
    # to search the key file paths then the value is written to the database
    elif in_key_id == "FSKP_EK":
        output_derived_key = get_fskpkey_hsm_server(in_key_id) # load secret FSKP_EK key in the HSM
        info_print('[HSM] Setting FSKP_EK value = ' + output_derived_key)
        output_derived_key = str_to_hex(output_derived_key)
        return hsm_server_store_derived_key_to_key_database(output_key_id, output_derived_key)
    elif in_key_id == "FSKP_AK":
        output_derived_key = get_fskpkey_hsm_server(in_key_id) # load secret FSKP key in the HSM
        info_print('[HSM] Setting FSKP_AK value = ' + output_derived_key)
        output_derived_key = str_to_hex(output_derived_key)
        return hsm_server_store_derived_key_to_key_database(output_key_id, output_derived_key)

    else:
        input_kdf_key = hsm_server_search_key_database(in_key_id)
        if input_kdf_key == None: # if search failed - this is unexpected - return FAILURE
            return False # or raise an exception

    info_print('[HSM] Derive %s using %s'  %(output_key_id, in_key_id))

    output_derived_key = nist_sp800_108_kdf(input_kdf_key, in_label, in_context)
    info_print('[HSM] Derived key is ' + hex_to_str(output_derived_key))

    return hsm_server_store_derived_key_to_key_database(output_key_id, output_derived_key)

'''
@brief The routine requests HSM server to search the key_id in the database
 If it is not found, then HSM server should perform kdf derivation
 and store the {key, value} pair in its database
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation
 OEM HSM KDF must be implemented via NIST SP800 108 KDF in counter mode with
 counter encoded as little-endian 32 bit counter

@param[in] in_key_id A string key ID and is to be used as input key for the KDF.
                     Type: string in ASCII.
                     Example: "SBK", "SBK_BCT_KDK_71f920fa275127a7b60fa4d4d41432a3"

@param[in] in_label The derivation label, to be used as input for the KDF.
                    Type: string of hex bytes.
                    Example: "00000000000000000000000000000000"

@param[in] in_context The derivation context, to be used as input for the KDF.
                      Type: string of hex bytes.
                      Example: "01010000", can be empty - ""

@param[in] output_key_id The string key ID of newly derived and stored inside OEM HSM key.
                         Type: string in ASCII.
                         Example: "SBK_BCT_DK_43c191bf6d6c3f263a8cd0efd4a058ab"
@retval True for success, False otherwise
'''
def oem_hsm_kdf(in_key_id, in_label, in_context, output_key_id):
    # send to OEM HSM device/server
    result_from_hsm_server = send_to_hsm_server_kdf(in_key_id, in_label, in_context, output_key_id)
    return result_from_hsm_server

'''
@brief The routine performs aesgcm operation on the HSM server
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@retval buff_sig for the encrypted buffer
        tag Tag for the tag value
'''
def hsm_server_aes_gcm(plain_text_buf, in_aad, iv, enc_dk_key):
    verify_bytes = 0
    base_name = script_dir + 'v3_gcm_' + pid
    raw_name = base_name + '.raw'
    result_name = base_name + '.out'
    # check tag and verify_file are both defined

    raw_file = open_file(raw_name, 'wb')
    plain_text_buf_len = len(plain_text_buf)

    key_bytes = len(enc_dk_key)/2
    keysize_bytes = int_2byte_cnt(key_bytes)
    len_bytes = int_2byte_cnt(plain_text_buf_len)
    enc_bytes = len(plain_text_buf)
    dest_bytes = plain_text_buf_len
    result_bytes = len(result_name) + 1
    iv_bytes = len(iv)/2 #len(str_to_hex(iv))/2
    aad_bytes = len(in_aad)/2 #len(binascii.hexlify(in_aad))/2

    tag_bytes = 0

    buff_dest = "0" * dest_bytes

    # to write to file in the following order:
    # sizes for: key, keysize, length, buf, buff_dest, result_name, iv, aad, tag, verify,
    # data of: key, key size, length, buffer, buff_dest, result_name, iv, add, tag, verify
    # Note: verify, if non-zero in length, is the original file to be verified against,
    #       so buf will be the encrypted content

    num_list = [key_bytes, keysize_bytes, len_bytes, enc_bytes, dest_bytes, result_bytes, iv_bytes, aad_bytes, tag_bytes, verify_bytes]
    for num in num_list:
        arr = int_2bytes(4, num)
        write_file(raw_file, arr)

    write_file(raw_file, str_to_hex(enc_dk_key))
    arr = int_2bytes(keysize_bytes, key_bytes)
    write_file(raw_file, arr)
    arr = int_2bytes(len_bytes, plain_text_buf_len)
    write_file(raw_file, arr)
    write_file(raw_file, bytes(plain_text_buf))
    write_file(raw_file, buff_dest.encode("utf-8"))
    write_file(raw_file, result_name.encode("utf-8"))
    nullarr = bytearray(1)
    nullarr[0] = 0          # need this null for char*
    write_file(raw_file, nullarr)
    if iv_bytes > 0:
        write_file(raw_file, str_to_hex(iv))
    if aad_bytes > 0:
        write_file(raw_file, str_to_hex(in_aad))
    raw_file.close()

    command = exec_file(TegraOpenssl)
    command.extend(['--aesgcm', raw_name])
    command.extend(['--verbose'])

    ret_str = run_command(command)

    if check_file(result_name):
        result_fh = open_file(result_name, 'rb')
        buff_sig = bytearray(result_fh.read()) # Return data to caller
        result_fh.close()
        os.remove(result_name)
    start = ret_str.find('tag')
    tag_str_len = 4
    if (start > 0):
        if tag_bytes > 0:
            end = start + tag_str_len + int(tag_bytes * 2)
        else:
            end = len(ret_str)
        tag = ret_str[start+tag_str_len:end]
    os.remove(raw_name)
    return buff_sig, tag

'''
@brief The routine sends the aesgcm operation request to the HSM server
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] plain_text_buf The input plain text to be encrypted (AES GCM) in binary (byte array) format.
@param[in] in_aad The additional authenticated data (AAD GCM) in binary (byte array) format.

@param[in] key_id The derived key string for this operation
                      Example: "SBK_BCT_DK_43c191bf6d6c3f263a8cd0efd4a058ab"
@param[in] rdm_iv The flag to indicate if iv will be randomly generated

@param[in] in_iv The existing iv

@retval
       True for success, False otherwise
       encrypted_buf The encrypted data or None
       iv Either it is generated by HSM server in string, or in_iv, or None
       tag The GCM tag, or None
'''
def send_to_hsm_server_aes_gcm(plain_text_buf, in_aad, key_id, rdm_iv, in_iv):
    # search for a cached/stored derived key in the HSM device/server key database by key_id
    enc_dk_key = hsm_server_search_key_database(key_id)
    if enc_dk_key == None: # if key not found:
        return False, None, None, None # return error
    if rdm_iv:
        # randomly generate IV inside OEM HSM to append to aad:
        iv = hex_to_str(random_gen(IV_SIZE))
        encrypted_buf, tag = hsm_server_aes_gcm(plain_text_buf, in_aad + iv, iv, enc_dk_key)

    else:
        # the add already has iv in it, so just use the iv passed in to do aes-gcm
        iv = in_iv
        encrypted_buf, tag = hsm_server_aes_gcm(plain_text_buf, in_aad, iv, enc_dk_key)
    return True, encrypted_buf, iv, tag

'''
@brief The routine requests HSM server to perform the aesgcm operation
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] plain_text_buf The input plain text to be encrypted (AES GCM) in binary (byte array) format.
@param[in] in_aad The additional authenticated data (AAD GCM) in binary (byte array) format.

@param[in] key_id The derived key string for this operation
                      Example: "SBK_BCT_DK_43c191bf6d6c3f263a8cd0efd4a058ab"
@param[in] rdm_iv The flag to indicate if iv will be randomly generated
                      Default to True so iv will be randomly generated

@param[in] in_iv The existing iv
                      Default to None so it's randomly generated later and returned as iv

@retval
       True for success, False otherwise
       encrypted_buf The encrypted data
       iv Either it is generated by HSM server in string, or in_iv
       tag The GCM tag
'''
def oem_hsm_aes_gcm(plain_text_buf, in_aad, key_id, rdm_iv = True, in_iv = None):
    result, encrypted_buf, iv, tag = send_to_hsm_server_aes_gcm(plain_text_buf, in_aad, key_id, rdm_iv, in_iv)
    return result, encrypted_buf, iv, tag

'''
@brief The routine mimics the hmacsha handling on the HSM server.
@Note: [REFERENCE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] plain_text_buf The input plain text to be operated on in binary (byte array) format.

@param[in] key_id The derived key string for this operation
                      Example: "FSKP_AK_43c191bf6d6c3f263a8cd0efd4a058ab"

@retval
       True for success, False otherwise
       hmac_buf The finished data
'''
def send_to_hsm_server_hmacsha(plain_text_buf, key_id):
    # search for a cached/stored derived key in the HSM device/server key database by key_id
    hmac_key = hsm_server_search_key_database(key_id)
    if hmac_key == None: # if key not found:
        return False, None # return error

    tmpf_in = 'tmp_hmacsha.in'
    tmpf_out = 'tmp_hmacsha.mac'

    with open_file(tmpf_in, 'wb') as f:
        write_file(f, plain_text_buf)

    runcmd = 'openssl dgst -sha256 -mac hmac -macopt hexkey:%s -binary -out %s %s' % (hmac_key, tmpf_out, tmpf_in)
    info_print('[HSM] calling %s' % runcmd)
    try:
        subprocess.check_call(runcmd, shell=True)
    except subprocess.CalledProcessError:
        info_print("[HSM] ERROR: failure in running %s" % runcmd)
        exit_routine()
    finally:
        os.remove(tmpf_in)

    with open_file(tmpf_out, 'rb') as f:
        hmac = f.read()

    os.remove(tmpf_out)

    info_print('[HSM] hmacsha256 is done... return')

    return True, hmac

'''
@brief The routine sends the hmacsha request to the HSM server.
@Note: [REQUIRE]
@Note: This routine is expected to be replaced by OEM's own HSM implementation

@param[in] plain_text_buf The input plain text to be operated on in binary (byte array) format.

@param[in] key_id The derived key string for this operation
                      Example: "FSKP_AK_43c191bf6d6c3f263a8cd0efd4a058ab"

@retval
       hmac_buf The finished data or throws exception for failure
'''
def oem_hsm_hmacsha(plain_text_buf, key_id):
    result, hmac_buf = send_to_hsm_server_hmacsha(plain_text_buf, key_id)
    if result == False:
        raise tegrasign_exception('[HSM] Please check %s for % as hmac-sha operation did not complete' \
        %(TegraSign_v3_Keystore , key_id))
    return hmac_buf
