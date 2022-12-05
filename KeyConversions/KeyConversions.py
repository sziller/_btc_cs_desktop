import ecdsa
import codecs
import hashlib
import base58
import os
from btc_sziller_Class_package import *
from IntegerValidation import ValidateString as VaSt
from Validate import ValidateKeys as VaKe
from NumeralSystems import NumeralSystemConversions as NSCo
from CryptographyApplied import CustomMadeCryptography as CMCy


"""
Use of words: Formats
    hex-string:     string type data, made up of only hex characters: 0 1 2 3 4 5 6 7 8 9 a b c d e f A B C D E F
                    also considered to be of even lenght. If odd length given, leading zero is added
    mnemonic:       a Base2048 representation of 
    bin-string:     string type data, made up of only binary        characters: 0, 1
                    Keep in mind! bin-str are made up of groups of 11!!!
                    Binstrings represent data in base-2048 numeral system! Thats 2^11.
    byte-string:
"""

"""
Data as flowing through key management: NOT GENERALIZED - specifics for Bitcoin!
                    
Seed_               A number (of any size).
                    In our case a seed is a 2^256 magnitude number. Indistinguishabel from a private key in that sense. 
                    Used as root for any Deterministic Private key generation scheme.
                    The starting value of any tree or chain type Private key family.
                    Format: any practical format is accepted.
                            - hexstring (32 byte) - (64 digits)
                            - mnemonic words
Private Key:        A number of 2^256 magnitude. 
                    Used a base to generate any key in any format originating from this private key.
                    Format: any practical format is accepted.
                        - hexstring                         :   29 0e 97 89 3a  ... (32B / 64 chars): 1.15 x 10^77
                        - binary                            :   b'\xb7,n^\x1e\x12P. (32 byte)       : 1.15 x 10^77
                        - mnemonic words                    :   beef ahead raw  ... (24 words)  ...checksummed
                        - base2048 list                     :   [160, 41, 1428  ... (24 ints)   ...checksummed
                        - (W)allet (I)mport (F)ormat        :   (5) KVHGnn7     ... (51 chars)  ...checksummed
                        - (W)allet (I)mport (F)ormat comp.  :   (L/K) 4bppg     ... (52 chars)  ...checksummed
Public Key:         In fact 2 coordinates of a point on the y^2 = x^3 + 7 curve.
                    This is the Number to use in order to spend bitcoins, this number can be published freely (...)
                    P2PK uses this number to lock funds to (with the additional signature)
                    Format: 2 usual hex formats:
                        - hexstring (uncomp.) < extr.redund.:   (04)    9D BF   ... (32+32+1B / 130 chars)
                        - hexstring (comp.)                 :   (02/03) 9D BF   ... (   32+1B /  66 chars)
Public Key Hash:    A twice SHA256 hashed version of the public key.
                    The format used by P2PKH to lock funds (with the additional signature)
                    It is substantially shorter than a public key! (security???)
                        - hexstring                         :   b7 2c 6e 5e     ... (20B / 40 chars)
                        - binary                            :   b'Y\x10RQ\x04   ... (20B)
Binary

"""


def si_print(string="", switch=True, on=True):
    """=== Function name: si_print =====================================================================================
    Basic messaging tool. Optional print on screen regulated with an AND command using <on> and <switch>
    :param string:  the strint to be optionally printed.
    :param switch:  bool - one of the booleans to affect behaviour
    :param on:      bool - one of the booleans to affect behaviour
    :return: nothing
    =============================================================================================== by Sziler ==="""
    if on and switch:
        print(string)


def pubkey_from_prvkey_hxstr(prvkey_hxstr: str = "", compressed=False) -> str:
    """=== Function name: pubkey_from_prvkey_hxstr ===============================================================
        Function converts a bitcoin private key of size 2^256 into a bitcoin public key.
        Input is a hex-string (as defined in the head section of this file)
        Output is
        Uncompressed Public key is the concatinated X, Y coordinates in that order
        Compressed   Public key is only one coordinate plus a bit to show whitch side of the elliptic curve it is on.
        :param prvkey_hxstr: hexstring format number of magnitude 2^256
        :param compressed: bool - True for compressed, False for uncompressed public key.
        :return public key: x, y coordinates on the standard elliptic curve used by the Bitcoin system
                            in hex-string format
        ============================================================================================== by Sziller ==="""
    if VaKe.validate_prvkey_hxstr(prvkey_hxstr=prvkey_hxstr):
        signing_key = ecdsa.SigningKey.from_string(codecs.decode(prvkey_hxstr, "hex"), curve=ecdsa.SECP256k1)
        verification_key = signing_key.verifying_key
        return codecs.decode(b'04' + codecs.encode(verification_key.to_string(), 'hex'), "hex")
    else:
        raise Exception("Entered variable cannot be interpretted as valid 2^256 private key in hexstring!"
                        "\n sais: pubkey_hxstr_from_prvkey_hxstr() at KeyConversions.py") from None


def pubkey_hxstr_from_prvkey_hxstr(prvkey_hxstr: str = "", compressed=False) -> str:
    """=== Function name: pubkey_hxstr_from_prvkey_hxstr ===============================================================
    Function converts a bitcoin private key of size 2^256 into a bitcoin public key.
    Both input and output are hex-string (as defined in the head section of this file)
    Uncompressed Public key is the concatinated X, Y coordinates in that order
    Compressed   Public key is only one coordinate plus a bit to show whitch side of the elliptic curve it is on.
    :param prvkey_hxstr: hexstring format number of magnitude 2^256
    :param compressed: bool - True for compressed, False for uncompressed public key.
    :return public key: x, y coordinates on the standard elliptic curve used by the Bitcoin system
                        in hex-string format
    ============================================================================================== by Sziller ==="""
    if VaKe.validate_prvkey_hxstr(prvkey_hxstr=prvkey_hxstr):
        signing_key = ecdsa.SigningKey.from_string(codecs.decode(prvkey_hxstr, "hex"), curve=ecdsa.SECP256k1)
        verification_key = signing_key.verifying_key
        return "04" + str(codecs.encode(verification_key.to_string(), 'hex'), 'ascii')
    else:
        raise Exception("Entered variable cannot be interpretted as valid 2^256 private key in hexstring!"
                        "\n sais: pubkey_hxstr_from_prvkey_hxstr() at KeyConversions.py") from None

# --- Creating public key hash -------------------------------------------------------------------- START   ------------


def pubkeyhash_hxstr_from_pubkey_hxstr(pubkey_hxstr: str) -> str:
    """=== Function name: pubkeyhash_hxstr_from_pubkey_hxstr =========================================================
    Function converts a bitcoin public key into a bitcoin public key hash.
    Both input and output is a hexstring (as defined in the head section of this file)
    :param pubkey_hxstr: hexstring format number
    :return public key hash: hash of the public key as used by the Bitcoin system in hex-string format
    ============================================================================================== by Sziller ==="""
    pkh1 = hashlib.sha256(codecs.decode(pubkey_hxstr, "hex")).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(pkh1)
    public_key_hash = ripemd160.digest()
    return bytes.decode(codecs.encode(public_key_hash, "hex"))


def pubkeyhash_from_pubkey_hxstr(pubkey_hxstr: str):
    """=== Function name: pubkeyhash_from_pubkey_hxstr =================================================================
    Function converts a bitcoin public key into a bitcoin public key hash.
    Input is a hexstring (as defined in the head section of this file)
    Output is a bytestring.
    :param pubkey_hxstr: hexstring format number
    :return public key hash: hash of the public key as used by the Bitcoin system as byte-string
    ============================================================================================== by Sziller ==="""
    pkh = hashlib.sha256(codecs.decode(pubkey_hxstr, "hex")).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(pkh)
    return ripemd160.digest()

# --- Creating public key hash -------------------------------------------------------------------- ENDED   ------------

# --- Creating binary bitcoin address ------------------------------------------------------------- START   ------------


def binaddr_hxstr_from_pubkeyhash_hxstr(pubkeyhash_hxstr: str, mainnet: bool = True):
    """=== Function name: binaddr_hxstr_from_pubkeyhash_hxstr ==========================================================
    Function turns a public key hash (entered as hex-string) into a binary address in hex-string format.
    <mainnet> bool is True for mainnet, False for testnet
    :param pubkeyhash_hxstr: bitcoin style pubkeyhash in hex-string format
    :param mainnet: bool - True if address goes to mainnet, False for testnet
    :return the binary address as a hex-string
    ============================================================================================== by Sziller ==="""
    publickeyhash_bstr = codecs.decode(pubkeyhash_hxstr, "hex")
    version_codes_bytes = {True: '\00', False: '\01'}[mainnet]
    lead_and_middlepart = codecs.encode(version_codes_bytes) + publickeyhash_bstr
    lead_and_middlepart_twicehashed = hashlib.sha256(hashlib.sha256(lead_and_middlepart).digest()).digest()
    checksum = lead_and_middlepart_twicehashed[:4]
    binary_address = lead_and_middlepart + checksum
    return bytes.decode(codecs.encode(binary_address, "hex"))


def binaddr_from_pubkeyhash(pubkeyhash, mainnet: bool = True):
    """=== Function name: binaddr_from_pubkeyhash ======================================================================
    Function turns a public key hash (entered as byte-string) into a binary address as byte-string.
    <mainnet> bool is True for mainnet, False for testnet
    :param pubkeyhash: bitcoin style pubkeyhash in byte-string format
    :param mainnet: bool - True if address goes to mainnet, False for testnet
    :return the binary address as a byte-string
    ============================================================================================== by Sziller ==="""
    version_codes_bytes = {True: '\00', False: '\01'}[mainnet]
    lead_and_middlepart = codecs.encode(version_codes_bytes) + pubkeyhash
    lead_and_middlepart_twicehashed = hashlib.sha256(hashlib.sha256(lead_and_middlepart).digest()).digest()
    checksum = lead_and_middlepart_twicehashed[:4]
    return lead_and_middlepart + checksum

# --- Creating binary bitcoin address ------------------------------------------------------------- ENDED   ------------

# --- Creating bitcoin address -------------------------------------------------------------------- START   ------------


def address_from_binaddr_hxstr(binaddr_hxstr: str) -> str:
    """=== Function name: address_from_binaddr_hxstr ===================================================================
    Function turns the binary address into a user-friendly bitcoin address in a string.
    :param binaddr_hxstr: binary address as a hex-string
    :return a bitcoin style address as a string
    ============================================================================================== by Sziller ==="""
    binaddress_bstr = codecs.decode(binaddr_hxstr, "hex")
    return base58.b58encode(binaddress_bstr).decode('ascii')


def address_from_binaddr(binaddr: bytearray) -> str:
    """=== Function name: address_from_binaddr =========================================================================
    Function turns the binary address (represented as byte-array) into a user-friendly
    bitcoin address represented as a string.
    :param binaddr: binary address as a byte-array
    :return a bitcoin style address as a string
    ============================================================================================== by Sziller ==="""
    return base58.b58encode(binaddr).decode('ascii')

# --- Creating bitcoin address -------------------------------------------------------------------- ENDED   ------------


def pubkeyhash_hxstr_from_address(address: str) -> str:
    """=== Function name: pubkeyhash_hxstr_from_address ================================================================
    script reconverts an address into a public key hash
    :param address: string - a Bitcoin type address as string.
    :return: dict - containing the public key hash in string format
    ============================================================================================== by Sziller ==="""
    # step 1: we revert the base58 operation on the address, receive the Binary Address
    # and convert it into a string - in order to get a readable PKH:
    reverted__bytes = codecs.encode((base58.b58decode(bytes(address, "ascii"))), "hex")
    reverted_string = (bytes.decode(reverted__bytes))

    # step 2: we truncate (front and back) the BA in both byte and string format to get the PKH:
    public_key_hash_read__bytes = codecs.decode(reverted__bytes[2:-8], "hex")
    public_key_hash_read_string = reverted_string[2:-8]

    # step 3: we read the checksum of the Binary Address
    checksum_read__bytes = codecs.decode(reverted__bytes[-8:], "hex")
    # checksum_read_string = reverted_string[-8:]
    # public_key_hash_read__bytes = codecs.decode(public_key_hash_read_string.encode(), "hex")

    # step 4: we recreate a checksum, using Bitcoin's convention
    lead_and_middlepart = codecs.encode('\00') + public_key_hash_read__bytes
    lead_and_middlepart_twicehashed = hashlib.sha256(hashlib.sha256(lead_and_middlepart).digest()).digest()
    checksum_calculated__bytes = lead_and_middlepart_twicehashed[:4]
    # checksum_calculated_string = bytes.decode(codecs.encode(checksum_calculated__bytes, "hex"))

    # step 5: we compare the read and the calculated checksum values:
    valid = checksum_read__bytes == checksum_calculated__bytes
    if not valid:
        raise Exception("Invalid bitcoin address entered!\n"
                        " sais: pubkeyhash_hxstr_from_address() at KeyConversions.py") from None
    return public_key_hash_read_string


def address_from_privkey_hxstr(prvkey_hxstr: str) -> str:
    """=== Function name: address_from_privkey_hxstr ===================================================================
    Function is a compound way to create an address (string) from a private key (hex-string)
    :param prvkey_hxstr: a valid private key in hex-string format
    :return: a valid bitcoin address (string), from the entered private key (hex-string)
    ============================================================================================== by Sziller ==="""
    if VaKe.validate_prvkey_hxstr(prvkey_hxstr=prvkey_hxstr):
        pubkey_hxstr = pubkey_hxstr_from_prvkey_hxstr(prvkey_hxstr=prvkey_hxstr)
        pubkeyhash = pubkeyhash_from_pubkey_hxstr(pubkey_hxstr=pubkey_hxstr)
        binaddr = binaddr_from_pubkeyhash(pubkeyhash=pubkeyhash, mainnet=True)
        return address_from_binaddr(binaddr=binaddr)
    else:
        raise Exception("Entered variable cannot be interpretted as valid 2^256 private key in hexstring!"
                        "\n sais: address_from_privkey_hxstr() at KeyConversions.py") from None


def hexstr_value_bip39_checksum_creator(hexstr_value: str = ""):
    """=== Function name: hexstr_value_bip39_checksum_creator ==========================================================
    Function calculates a checksum.
    according to bip39: seeds - when stored as a mnemonic phrase - get a checksum attached.
    This function can be used when creating a binary representation of a seed, or
    when validating the binary representation
    :param hexstr_value: your base value in hexadecimal string format.
    :return: string - checksum as binary
    """
    nr_of_digits = len(hexstr_value)
    if nr_of_digits % 32 == 0:
        nr_of_bytes = nr_of_digits / 2
        nr_of_bits = int(nr_of_bytes * 8)
        b_checksum_length = int(nr_of_bits / 32)
        try:
            hex_in_bytes = codecs.decode(hexstr_value, "hex")
        except:
            raise Exception("ERROR: entered hexadecimal contains invalid characters!")
        hex_hashed_bytes = codecs.encode(hashlib.sha256(hex_in_bytes).digest(), "hex")  # default number will be hashed
        hex_hashed_decimal_int = int(hex_hashed_bytes, 16)
        hex_hashed_binary = NSCo.decimal_to_base(n=hex_hashed_decimal_int, base=2)
        binary_checksum_raw = hex_hashed_binary[:(-1 * (256 - b_checksum_length))]

        # if hash result's length in binary form is less then 256, it means, leading zeros were suppressed
        # these zeros must be re-added, in order to get the correct checksum
        binary_checksum = "{:{}}".format(binary_checksum_raw, '0' + ">" + str(b_checksum_length))
        return binary_checksum
    else:
        raise Exception("Basic conditions for function to be trigerred not met.")


def hexstr_to_binstr_bip39_converter(hxstr: str, messaging: bool = True):
    """=== Function name: hexstr_value_to_binstr_bip39_converter =======================================================
    Function converts the pure string representation of a hexadecimal number (hexstring) into
     a binary number with a chechsum attached. Checksum is calculated according to BIP39 standard.
    A didactic function for step-by-step understanding of BIP39 checksum creation.
    It's inverter is the > binstr_to_hexstr_value_bip39_converter <
    :param hxstr: your base value in hexadecimal string format.
                unintentionally thou, function also accepts hex in binary-hex format: b'........
    :param messaging: if you want verbose messages in console window.
    :return: string of binary digits
    ============================================================================================== by Sziller ==="""

    nr_of_digits = len(hxstr)
    if nr_of_digits % 32 == 0:
        nr_of_bytes = nr_of_digits / 2
        nr_of_bits = int(nr_of_bytes * 8)
        '''---------------------------------------------
        - branch 1: binary conversion of entered value -
        ---------------------------------------------'''
        value_dec = int(hxstr, 16)
        binary_value_raw = NSCo.decimal_to_base(n=value_dec, base=2)
        # if values magnitude is such, that it translates into binary with leading zeros
        # these zeros must be re-added
        # binary_value_raw might have to be converted to string!
        binary_value = "{:{}}".format(binary_value_raw, '0' + ">" + str(nr_of_bits))
        '''---------------------------------------------
        - branch 2: creating checksum                  -
        ---------------------------------------------'''
        binary_checksum = hexstr_value_bip39_checksum_creator(hexstr_value=hxstr)
        '''---------------------------------------------
        - attaching binary value and checksum          -
        ---------------------------------------------'''
        value_plus_checksum_binary = binary_value + binary_checksum
        return value_plus_checksum_binary
    else:
        raise Exception("Number of digits not appropriate!\n sais: hexstr_to_binstr_bip39_converter()"
                        "at KeyConversions.py")


def base2048_list_to_mnemonic_phrase_encoder(base2048_list: list = None,
                                             dictionary: dict = None):
    """=== Function name: base2048_list_to_mnemonic_phrase_encoder =====================================================
    It's inverter is the > mnemonic_phrase_to_base2048_list_decoder <
    Function turns a list of numbers (btw. 0 and 2047) into a bitcoin style mnemonic.
    You must provide the alphabet to use, depending on your language preferences.
    :param base2048_list:
    :param dictionary: the actual mnemonic alphabet as a dictionary (starting key: 0)
    :return: list of mnemonic words
    ============================================================================================== by Sziller ==="""
    return [dictionary[nr] for nr in base2048_list]


def mnemonic_phrase_to_base2048_list_decoder(mnemonic_phrase: list = None,
                                             dictionary: dict = None):
    """=== Function name: mnemonic_phrase_to_base2048_list_decoder =====================================================
    It's inverter is the > base2048_list_to_mnemonic_phrase_encoder <
    Function turns a bitcoin style mnemonic into a list of numbers (btw. 0 and 2047)
    :param mnemonic_phrase:
    :param dictionary: the necessary BIP39 dictionary in the proper language
    :return:
    ============================================================================================== by Sziller ==="""
    reverted_dict = {value: key for key, value in dictionary.items()}
    base2048_list = [reverted_dict[nr] for nr in mnemonic_phrase]
    return base2048_list


def mnemonic_from_prvkey_hxstr(prvkey_hxstr: str = "", dictionary: dict = None) -> list:
    """=== Function name: mnemonic_from_prvkey_hxstr ===================================================================

    EXTEND to handle zero input!!!

    Function turns a private key (hexstring format)
    into a mnemonic phrase.
    :param prvkey_hxstr:
    :param dictionary:
    :return:
    ============================================================================================== by Sziller ==="""
    if VaKe.validate_prvkey_hxstr(prvkey_hxstr=prvkey_hxstr):
        binstring = hexstr_to_binstr_bip39_converter(hxstr=prvkey_hxstr)
        base2048 = NSCo.binstr2048_to_base2048_list_converter(binstr2048=binstring)
        return base2048_list_to_mnemonic_phrase_encoder(base2048_list=base2048, dictionary=dictionary)
    else:
        raise Exception("Entered data not a valid Private key hexstring format!\n"
                        " sais: mnemonic_from_prvkey_hxstr() at KeyConversions.py") from None


def prvkey_wif_from_prvkey_hxstr(prvkey_hxstr: str, mainnet: bool = True, compressed: bool = True) -> str:
    """=== Function name: prvkey_wif_from_prvkey_hxstr =================================================================
    Function turns a hexstring format private key into a WIF format one.
    WIF or Wallet Import Format's are checksummed Base58 representations of a PrivateKey.
    WIF Private Keys can be Compressed or Uncompressed.
    It is the invert function of: prvkey_hxstr_from_prvkey_wif()
    :param prvkey_hxstr:    str -
    :param mainnet:         bool - True for Mainnet, False for
    :param compressed:      bool -
    :return: the WIF sting representation of the entered private key
    ============================================================================================== by Sziller ==="""
    if VaSt.validate_hexstring(string_in=prvkey_hxstr):
        prefix  = {True: '80',  False: 'ef'}[mainnet]
        flag    = {True: '01',  False: ''}[compressed]
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        versioned_hxstr = prefix + prvkey_hxstr + flag

        checksum_hexstr = CMCy.create_checksum_x_byte_hxstr(hxstr=versioned_hxstr, bytecount=4, front=True)

        versioned_checksummed_hxstr = versioned_hxstr + checksum_hexstr
        decimal = int(versioned_checksummed_hxstr, 16)
        return NSCo.decimal_to_base(n=decimal, base=58, stringmode=True, alphabet=alphabet)
    else:
        raise Exception("Invalid hexstring!\n sais prvkey_wif_from_prvkey_hxstr() at KeyConversions.py") from None


def prvkey_hxstr_from_prvkey_wif(prvkey_wif: str) -> str:
    """=== Function name: prvkey_hxstr_from_prvkey_wif =================================================================
    Function turns a WIF format private key into a hexstring format one.
    WIF or Wallet Import Format's are checksummed Base58 representations of a PrivateKey.
    WIF Private Keys can be Compressed or Uncompressed.
    It is the invert function of: prvkey_wif_from_prvkey_hxstr()
    :param prvkey_wif: the wif format of the private key.
    :return: the hexstring representation of the entered private key
    ============================================================================================== by Sziller ==="""

    if VaKe.validate_prvkey_wif(prvkey_wif=prvkey_wif, bytecount=4):
        reverted__bytes = codecs.encode((base58.b58decode(bytes(prvkey_wif, "ascii"))), "hex")
        reverted_hxstr_nochcksm = (bytes.decode(reverted__bytes))
        lead, prvkey, flag  = reverted_hxstr_nochcksm[:2], reverted_hxstr_nochcksm[2:66], reverted_hxstr_nochcksm[66:]
        return prvkey
    else:
        raise Exception("Entered string is not a valid Base58 number or checksum missmatch!"
                        "\n sais: prvkey_hxstr_from_prvkey_wif() at KeyConversions.py")


def pubkey_hxstr_compress(pubkey_hxstr: str) -> str:
    """=== Function name: pubkey_hxstr_compress ========================================================================
    Returns a compressed public key from an uncompressed one.
    :param pubkey_hxstr:
    :return:
    ============================================================================================== by Sziller ==="""
    if True:
        trunc = pubkey_hxstr[2:]
        length = int(len(trunc) / 2)
        x, y = trunc[:length], trunc[length:]
        if y[-1] in '02468aceACE':
            prefix = '02'
        else:
            prefix = '03'
        return prefix + x
    else:
        raise Exception("Entred variable is not a valid uncompressed public key!"
                        "\n sais: pubkey_hxstr_compress()  ") from None


def pubkey_hxstr_decompress(pubkey_hxstr: str, **kwargs) -> str:
    pass



'''

def compress(x: int, y: int) -> bytes:
    e_x = number_to_string(x, ecdsa.SECP256k1.order)  # encoded x
    return (b'\x03' + e_x) if y % 2 else (b'\x02' + e_x)


def uncompress(string: bytes, curve=ecdsa.SECP256k1) -> Point:

    class MalformedPoint(Exception):
        pass

    if string[:1] not in (b'\x02', b'\x03'):
        raise MalformedPoint("Malformed compressed point encoding")

    is_even = string[:1] == b'\x02'
    x = string_to_number(string[1:])
    order = curve.order
    p = curve.curve.p()
    alpha = (pow(x, 3, p) + (curve.curve.a() * x) + curve.curve.b()) % p
    try:
        beta = square_root_mod_prime(alpha, p)
    except SquareRootError as e:
        raise MalformedPoint(
            "Encoding does not correspond to a point on curve", e
        )
    if is_even == bool(beta & 1):
        y = p - beta
    else:
        y = beta
    if not ecdsa.point_is_valid(curve.generator, x, y):
        raise MalformedPoint("Point does not lie on curve")
    return Point(curve.curve, x, y, order)

'''

# ===============================================================================================================


def binstr_to_hexstr_value_bip39_converter(binstr: str = "", messaging: bool = True):
    """
    FUNCTION NAME: binstr_to_hexstr_value_bip39_converter
    Function converts the pure string representation of a binary number into a hexadecimal representation, assuming
    the entered number having had a checksum attached, according to BIP39.
    A didactic function for step-by-step understanding of BIP39 checksum decoding, and verification.

    It's inverter is the > hexstr_value_to_binstr_bip39_converter <
    :param binstr: your binary encoded, checksum extended binary string
    :param messaging: if you want verbose messages in console window.
    :return: string of hexadecimal digits
    """

    si_print("<| STARTING: binary string --> hexadecimal string formated value - bip39 converter", on=messaging)
    nr_of_digits = len(binstr)
    nr_of_bits = int(nr_of_digits * (32/33))
    nr_of_bytes = int(nr_of_bits / 8)
    nr_of_out_digits = nr_of_bytes * 2
    si_print("The entered binary's base number has a length of %s bits" % nr_of_bits, on=messaging)
    binary_value = binstr[:nr_of_bits]
    si_print("The entered binary's base number in binary is:\n %s" % binary_value, on=messaging)
    '''---------------------------------------------
    - branch 1: conversion to hexadecimal          -
    ---------------------------------------------'''
    decimal_value = int(binary_value, 2)
    si_print("The entered binary's base number in decimal is:\n %s" % decimal_value, on=messaging)
    hexadecimal_value_raw = NSCo.decimal_to_base(n=decimal_value, base=16, alphabet='0123456789abcdef')
    hexadecimal_value = "{:{}}".format(hexadecimal_value_raw, "0" + ">" + str(nr_of_out_digits))
    # value might have to be converted to string!
    # direction = {True: ">", False: "<"}[leading]
    # nr_of_digits = integer
    # "{:{}}".format(value, placeholder + direction + str(nr_of_bits))
    si_print("The entered binary's base number in hexadecimal is:\n %s" % hexadecimal_value, on=messaging)
    '''---------------------------------------------
    - branch 2: binstring validation               -
    ---------------------------------------------'''
    calculated_binary_checksum = hexstr_value_bip39_checksum_creator(hexstr_value=hexadecimal_value)
    nr_of_digits = len(hexadecimal_value)
    nr_of_bytes = nr_of_digits / 2
    nr_of_bits = int(nr_of_bytes * 8)
    b_checksum_length = int(nr_of_bits / 32)
    extracted_binary_checksum = binstr[(-1 * b_checksum_length):]
    '''---------------------------------------------
    - only answering if checksum validated         -
    ---------------------------------------------'''
    if calculated_binary_checksum == extracted_binary_checksum:
        return hexadecimal_value
    else:
        print("ERROR: invalid binary binary string entered: bip39 checksum error")
        return False


def generate_rnd_hxstr(bytesize: int = 32):
    """=== Function name: generate_rnd_hxstr ===========================================================================
    Using a built-in random function, function generates a 'bytesize'-d private key and returns it as a hexstring.
    :param bytesize: integer - length of the random number
    ============================================================================================== by Sziller ==="""
    rnd_prvkey_bytes = codecs.encode(os.urandom(bytesize), 'hex')
    return str(rnd_prvkey_bytes, 'ascii')  # returned value: <prvkey_hxstr>


def address_generator_shell(mode: int = 0,
                            prvkey_hxstr: str = "",
                            lead_list: list = None,
                            nr_of_max_try: int = 20,
                            check_lead_only: bool = False,
                            messaging: bool = False):
    """=== Function name: address_generator_shell ======================================================================

    The point of this function is to create an address!
    Method to create addresses in different ways. Explained under 'mode' argument.

    :param mode: 0, 1 or 2 at this point:
                0: RANDOM keypair will be generated, using built in random generator
                1: ENTERED private key will be turned into an address
                2: VANITY pair, whose address contains one of your 'lead' strings will be generated. Takes longer...
    :param prvkey_hxstr: your basic private key nr in original hexadecimal format, stored as a string.
    :param lead_list: list of initial characters, you want to be part of your public key.
    :param nr_of_max_try:
    :param check_lead_only:
    :param messaging: if you need printed messages in console while running.
    :return:
    ============================================================================================== by Sziller ==="""

    # check = {'0': 0, '1': 0, '2': 0, '3': 0, '4': 0, '5': 0, '6': 0, '7': 0, '8': 0, '9': 0,
    #  'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0, 'g': 0, 'h': 0, 'i': 0, 'j': 0, 'k': 0, 'l': 0, 'm': 0,
    #  'n': 0, 'o': 0, 'p': 0, 'q': 0, 'r': 0, 's': 0, 't': 0, 'u': 0, 'v': 0, 'w': 0, 'x': 0, 'y': 0, 'z': 0,
    #  'A': 0, 'B': 0, 'C': 0, 'D': 0, 'E': 0, 'F': 0, 'G': 0, 'H': 0, 'I': 0, 'J': 0, 'K': 0, 'L': 0, 'M': 0,
    #  'N': 0, 'O': 0, 'P': 0, 'Q': 0, 'R': 0, 'S': 0, 'T': 0, 'U': 0, 'V': 0, 'W': 0, 'X': 0, 'Y': 0, 'Z': 0}

    condition = False
    address = ""
    counter = 0
    while not condition:
        # f RANDOM or VANITY mode...
        if mode in [0, 2]:
            # a random 256-bit number is generated.
            # Format: b'1db7e439b11474ce30f79a067fc82b094372303c2554c35b21c81f54fbe703bf'
            rnd_prvkey_bytes = codecs.encode(os.urandom(32), 'hex')
            # turning the byte-format into hexstring
            # Format: 1db7e439b11474ce30f79a067fc82b094372303c2554c35b21c81f54fbe703bf
            prvkey_hxstr = str(rnd_prvkey_bytes, 'ascii')
            si_print(string="\na randomly generated private key: %s" % prvkey_hxstr, on=messaging)
            if (not messaging) and (mode != 0):
                print('... %s' % counter)

        address = address_generator(prvkey_hxstr=prvkey_hxstr, messaging=messaging)['address']
        if mode in [0, 1]:
            condition = True
            si_print(string="(%s) I've converted an address: " % counter + str(address), on=messaging)
        else:
            for _ in lead_list:
                if check_lead_only: condition = address[1:].startswith(_)
                else: condition = _ in address
        counter += 1
        if counter == nr_of_max_try:
            condition = True
    # Generating a (W)allet (I)mport (F)ormat encoding of the PRIVATE-KEY!
    wif = prvkey_wif_from_prvkey_hxstr(prvkey_hxstr=prvkey_hxstr, mainnet=True, compressed=True)

    # Function returns a dictionary with the following data:
    # 'prvkey_hxstr'    : the generated / entered private key as a hexstring
    # 'wif'             : the generated / entered private key in WalletImportFormat
    # 'address'         : a receiving address in base58 coding. It is a one-on-one match to the private key.
    return {'prvkey_hxstr': prvkey_hxstr,
            'wif': wif,
            'address': address}


def address_generator(prvkey_hxstr, messaging=False):
    """=== Function name: address_generator ============================================================================
    The way addresses in Bitcoin are generated is decribed in this function step-by-step.
    You basically have a private key initially. It is received in hexstring format.
    1. you create a public key using ECDSA
    2. you create a hash of that key using sha256 and ripemd160 consequently
    3. out of the public key hash, you create a binary address by adding a byte, making a checksum, by
       hashing twice with sha256, and adding it to the hash
    4. you use a reversible BASE58 encoding in order to get the address

    Basic script to create different data from a private key.
    it returns different data derived from the private key during the process.
    :param prvkey_hxstr:
    :param messaging:
    :return: dictionary:
    ============================================================================================== by Sziller ==="""

    '''----------------------------------------------------------------
    - creating PUBLIC KEY                                       START -
    ----------------------------------------------------------------'''
    # from the hexadecimal private key, we create a public key, using SECP256k1
    # first we get an object, then we turn this objects actual variable into a string.
    print("<prvkey_hxstr>: {}".format(prvkey_hxstr))
    signing_key = ecdsa.SigningKey.from_string(codecs.decode(prvkey_hxstr, "hex"), curve=ecdsa.SECP256k1)
    si_print(string="SigningKey object was created:                                       done",
             on=messaging)
    verification_key = signing_key.verifying_key
    public_key = "04" + str(codecs.encode(verification_key.to_string(), 'hex'), 'ascii')
    si_print(string="PublicKey was created: (see below)                                   done\n  %s" % public_key,
             on=messaging)
    '''----------------------------------------------------------------
    - creating PUBLIC KEY                                       ENDED -
    ----------------------------------------------------------------'''

    '''----------------------------------------------------------------
    - creating PUBLIC KEY HASH                                  START -
    ----------------------------------------------------------------'''
    # public key is hashed twice: 1.) SHA256 2.)ripemd160
    # step 1:
    print("<public_key>: {}".format(public_key))
    pkh1 = hashlib.sha256(codecs.decode(public_key, "hex")).digest()
    # step 2:
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(pkh1)
    public_key_hash = ripemd160.digest()
    public_key_hash_string = bytes.decode(codecs.encode(public_key_hash, "hex"))
    si_print(string="PublicKeyHash was created: (see below)                               done\n  %s"
                         % public_key_hash_string,
                  on=messaging)
    '''----------------------------------------------------------------
    - creating PUBLIC KEY HASH                                  ENDED -
    ----------------------------------------------------------------'''

    '''----------------------------------------------------------------
    - creating BINARY ADDRESS (base for public ADDRESS)         START -
    ----------------------------------------------------------------'''

    # null-byte + public key hash + checksum
    # |-------------------------|        /|\
    #  hashed twice using sha256          |
    #   first 4 bytes become the checksum |
    version_codes_bytes = {'mainnet': '\00'}
    lead_and_middlepart = codecs.encode(version_codes_bytes['mainnet']) + public_key_hash
    lead_and_middlepart_twicehashed = hashlib.sha256(hashlib.sha256(lead_and_middlepart).digest()).digest()
    checksum = lead_and_middlepart_twicehashed[:4]
    checksum_string = bytes.decode(codecs.encode(checksum, "hex"))
    binary_address = lead_and_middlepart + checksum
    binary_address_string = bytes.decode(codecs.encode(binary_address, "hex"))
    displayed_binary_address = binary_address_string[0:2] + \
                               " " + \
                               binary_address_string[2:-8] + \
                               " " + \
                               binary_address_string[-8:]
    # MeOp.si_print(string="Binary Address was created: (see below)                              done\n  %s"
    #                      % displayed_binary_address,
    #               on=messaging)
    '''----------------------------------------------------------------
    - creating BINARY ADDRESS (base for public ADDRESS)         ENDED -
    ----------------------------------------------------------------'''

    '''----------------------------------------------------------------
    - converting BINARY ADDRESS into readable ADDRESS           START -
    ----------------------------------------------------------------'''
    # base58 operation is reversible, it is not a hashing algorithm.
    address = base58.b58encode(binary_address).decode('ascii')
    '''----------------------------------------------------------------
    - converting BINARY ADDRESS into readable ADDRESS           ENDED -
    ----------------------------------------------------------------'''
    answer = {'private_key': prvkey_hxstr,
              'public_key': public_key,
              'public_key_hash': public_key_hash_string,
              'address': address,
              'checksum': checksum_string
              }
    return answer


def mnemonic_to_seed_bip39(sentence: str, password: str, saltlead: str = "mnemonic") -> str:
    """=== Function name: mnemonic_to_seed =============================================================================
    """
    salt_bytes = bytes(saltlead + password, "utf-8")
    print("sentence:\n{}".format(sentence) )
    words_bytes = bytes(sentence, "utf-8")
    seed_bytes = hashlib.pbkdf2_hmac('sha512', words_bytes, salt_bytes, 2048)
    return bytes.decode(codecs.encode(seed_bytes, 'hex'))


def manual_seed_creator(keylist: list,
                        numeral_system: int,
                        key_base: int = 16,
                        binary_power: int = 256,
                        messaging: bool = True,
                        dice_style: bool = True):
    """=== Function name: manual_seed_creator ==========================================================================
    Actual working horse of the seed creator, when starting with dice tosses.

    :param keylist: the dice too list (of any numerical base) made up of decimal values
    :param numeral_system: numeral system of your dice
    :param key_base: system for the seed to be in: 16 is preferred
    :param binary_power: strength of the code: 256 is preferred
    :dice_style: if 0 is included in the toss-set.
                 If a 'dice' has zero on it (...) a zero toss obviously is considered a 0.
                 If no zero included, then the largest possible toss (the base) is considered zero, az the base never
                 occures in the set anyway.
    :param messaging:
    :return:
    ============================================================================================== by Sziller ==="""
    si_print("First step accomplished: you've created a manual keylist:\n%s" % keylist, on=messaging)
    alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
    decimal_value = NSCo.list_into_decimal(toss_list=keylist,
                                           base=numeral_system,
                                           dice_style=dice_style)
    si_print("...it's decimal value is:\n%s" % decimal_value, on=messaging)
    final_key_incomplete_keybase = NSCo.decimal_to_base(n=decimal_value,
                                                        base=key_base,
                                                        stringmode=True,
                                                        alphabet=alphabet)
    nr_of_digits = len(final_key_incomplete_keybase)
    si_print("Your hexadecimal number is: %s" % final_key_incomplete_keybase, on=messaging)
    si_print("Your hexadecimal number turned out to be of %s digits!" % nr_of_digits, on=messaging)
    nr_of_necessary_digits = NSCo.power_calc_for_base_to_binary(base=key_base, binary_power=binary_power)
    try:
        exact = True if nr_of_necessary_digits % int(nr_of_necessary_digits) == 0 else False
    except ZeroDivisionError:
        exact = False
    si_print("exact: %s" % exact, on=messaging)
    if exact:
        nr_of_necessary_digits = int(nr_of_necessary_digits)
    else:
        nr_of_necessary_digits = int(int(nr_of_necessary_digits) + 1)
        # return None
    si_print("nr_of_necessary_digits: %s" % nr_of_necessary_digits, on=messaging)
    if nr_of_digits != nr_of_necessary_digits:
        si_print("... so it was corrected:", on=messaging)
        if nr_of_digits < nr_of_necessary_digits:
            si_print("   leading 0-s were added!", on=messaging)
        else:
            si_print("   leading digit(s) was/were deleted!", on=messaging)
    final_key_extended = "{:{}}".format(final_key_incomplete_keybase, '0' + '>' + str(nr_of_necessary_digits))
    final_key = final_key_extended[int(-1 * nr_of_necessary_digits):]
    si_print("Your key in base %s is: %s" % (key_base, final_key), on=messaging)
    return {'seed': final_key}


def demo(prvkey_hxstr: str, msg_doc: bool = True):
    print("{}".format("-" * 105))
    print("privatekey_hexstring:            {:<72}".format(prvkey_hxstr))
    print("{}".format("-" * 105))
    # -----------------------------------------------------------------------------------
    # - mnemonic_from_prvkey_hxstr                                          START       -
    # -----------------------------------------------------------------------------------
    if msg_doc: print(mnemonic_from_prvkey_hxstr.__doc__)
    _privatekey_mnemonic = mnemonic_from_prvkey_hxstr(prvkey_hxstr=prvkey_hxstr, dictionary=BIP039)
    div = 6
    sect = int(len(_privatekey_mnemonic) / div)
    for i in range(div):
        if i == 0: lead, init, end = "privatekey_mnemonic: (list)", "[", ","
        elif i == div - 1: lead, init, end = "", " ", "]"
        else: lead, init, end = "", " ", ","
        print("{:<27}      {}{}{}".format(
            lead,
            init,
            ", ".join(["'" + _ + "'" for _ in _privatekey_mnemonic[i * sect: (i + 1) * sect]]),
            end))
    for i in range(div):
        if i: lead = ""
        else: lead = "privatekey_mnemonic: (str)"
        print("{:<27}      {:>72}".format(lead, " ".join(_privatekey_mnemonic[i * sect: (i + 1) * sect])))
    # -----------------------------------------------------------------------------------
    # - mnemonic_from_prvkey_hxstr                                          ENDED       -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - prvkey_wif_from_prvkey_hxstr                                        START       -
    # -----------------------------------------------------------------------------------
    if msg_doc:
        print("")
        print(prvkey_wif_from_prvkey_hxstr.__doc__)
    _prvkey_wif = prvkey_wif_from_prvkey_hxstr(prvkey_hxstr=prvkey_hxstr)
    print("prvkey_wif:                      {:<72}".format(_prvkey_wif))
    # -----------------------------------------------------------------------------------
    # - prvkey_wif_from_prvkey_hxstr                                        ENDED       -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - prvkey_hxstr_from_prvkey_wif                                        START       -
    # -----------------------------------------------------------------------------------
    if msg_doc:
        print("")
        print(prvkey_hxstr_from_prvkey_wif.__doc__)
    _prvkey_hxst = prvkey_hxstr_from_prvkey_wif(prvkey_wif=_prvkey_wif)
    print("recreated prvkey_hxst:           {:<72}".format(_prvkey_hxst))
    # -----------------------------------------------------------------------------------
    # - prvkey_hxstr_from_prvkey_wif                                        ENDED       -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - pubkey_from_prvkey_hxstr                                            START       -
    # -----------------------------------------------------------------------------------
    if msg_doc:
        print("")
        print(pubkey_from_prvkey_hxstr.__doc__)
    _pubkey = False # pubkey_from_prvkey_hxstr(prvkey_hxstr=prvkey_hxstr)
    print("pubkey                           {}".format(_pubkey))
    # print("...as bytes:")
    # print(bytes.decode(codecs.encode(_pubkey, "hex")))
    # -----------------------------------------------------------------------------------
    # - pubkey_from_prvkey_hxstr                                            ENDED       -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - pubkey_hxstr_from_prvkey_hxstr                                      START       -
    # -----------------------------------------------------------------------------------
    if msg_doc:
        print("")
        print(pubkey_hxstr_from_prvkey_hxstr.__doc__)
    _pubkey_hxstr = pubkey_hxstr_from_prvkey_hxstr(prvkey_hxstr=prvkey_hxstr)
    print("{:<20}{:>85}\n{:>105}\n{:>105}\n{:>105}\n{:>105}".
          format("publickey_hexstring:", *[_pubkey_hxstr[i:i + 32] for i in range(0, len(_pubkey_hxstr), 32)]))
    # -----------------------------------------------------------------------------------
    # - pubkey_hxstr_from_prvkey_hxstr                                      ENDED       -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - pubkey_hxstr_compress                                               START       -
    # -----------------------------------------------------------------------------------
    if msg_doc:
        print("")
        print(pubkey_hxstr_compress.__doc__)
    _pubkey_hxstr_compr = pubkey_hxstr_compress(pubkey_hxstr=_pubkey_hxstr)
    print("pubkey_hxstr_compr:              {:<72}".format(_pubkey_hxstr_compr))
    # -----------------------------------------------------------------------------------
    # - pubkey_hxstr_compress                                               ENDED       -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - pubkeyhash_from_pubkey_hxstr                                        START       -
    # -----------------------------------------------------------------------------------
    if msg_doc:
        print("")
        print(pubkeyhash_from_pubkey_hxstr.__doc__)
    _pubkeyhash = pubkeyhash_from_pubkey_hxstr(pubkey_hxstr=_pubkey_hxstr)
    print("pubkey hash binary:              {}".format(_pubkeyhash))
    # -----------------------------------------------------------------------------------
    # - pubkeyhash_from_pubkey_hxstr                                        ENDED       -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - pubkeyhash_hxstr_from_pubkey_hxstr                                  START       -
    # -----------------------------------------------------------------------------------
    if msg_doc:
        print("")
        print(pubkeyhash_hxstr_from_pubkey_hxstr.__doc__)
    _pubkeyhash_hxstr = pubkeyhash_hxstr_from_pubkey_hxstr(pubkey_hxstr=_pubkey_hxstr)
    print("pubkey hash hexstring:           {:<72}".format(_pubkeyhash_hxstr))
    # -----------------------------------------------------------------------------------
    # - pubkeyhash_hxstr_from_pubkey_hxstr                                  ENDED       -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - binaddr_from_pubkeyhash                                             START       -
    # -----------------------------------------------------------------------------------
    if msg_doc:
        print("")
        print(binaddr_from_pubkeyhash.__doc__)
    _binaddr = binaddr_from_pubkeyhash(pubkeyhash=_pubkeyhash)
    print("binaddr:                         {}".format(_binaddr))
    # -----------------------------------------------------------------------------------
    # - binaddr_from_pubkeyhash                                             ENDED       -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - binaddr_hxstr_from_pubkeyhash_hxstr                                 START       -
    # -----------------------------------------------------------------------------------
    if msg_doc:
        print("")
        print(binaddr_hxstr_from_pubkeyhash_hxstr.__doc__)
    _binaddr_hxstr = binaddr_hxstr_from_pubkeyhash_hxstr(pubkeyhash_hxstr=_pubkeyhash_hxstr)
    print("binaddr_hxstr:                   {:<72}".format(_binaddr_hxstr))
    # -----------------------------------------------------------------------------------
    # - binaddr_hxstr_from_pubkeyhash_hxstr                                 ENDED       -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - address_from_binaddr_hxstr                                          START       -
    # -----------------------------------------------------------------------------------
    if msg_doc:
        print("")
        print(address_from_binaddr_hxstr.__doc__)
    _address = address_from_binaddr_hxstr(binaddr_hxstr=_binaddr_hxstr)
    print("address: (from binaddr hxstr)    {:<72}".format(_address))
    # -----------------------------------------------------------------------------------
    # - address_from_binaddr_hxstr                                          ENDED       -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - address_from_binaddr                                                START       -
    # -----------------------------------------------------------------------------------
    if msg_doc:
        print("")
        print(address_from_binaddr.__doc__)
    _address = address_from_binaddr(binaddr=_binaddr)
    print("address: (from binaddr)          {:<72}".format(_address))
    # -----------------------------------------------------------------------------------
    # - address_from_binaddr                                                ENDED       -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - pubkey_hxstr_decompress                                               START     -
    # -----------------------------------------------------------------------------------
    # print(pubkey_hxstr_decompress.__doc__)
    # print(pubkey_hxstr_decompress(pubkey_hxstr=_pubkey_hxstr_compr))
    # -----------------------------------------------------------------------------------
    # - pubkey_hxstr_decompress                                               ENDED     -
    # -----------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------
    # - pubkeyhash_hxstr_from_address                                       START       -
    # -----------------------------------------------------------------------------------
    if msg_doc:
        print("")
        print(pubkeyhash_hxstr_from_address.__doc__)
    _pubkeyhash_hxstr = pubkeyhash_hxstr_from_address(address=_address)
    print("pubkey hash hexstring: (check)   {:<72}".format(_pubkeyhash_hxstr))
    # -----------------------------------------------------------------------------------
    # - pubkeyhash_hxstr_from_address                                       ENDED       -
    # -----------------------------------------------------------------------------------


if __name__ == "__main__":

    _privatekey_hexstring = str(input("Enter private key in hexstring format: "))
    demo(prvkey_hxstr=_privatekey_hexstring, msg_doc=True)
    '''
    address_in = '1MiL12shZXpPAxtVgMiefQHU5XAqXrZfsY'
    pkh_hxstr = pubkeyhash_hxstr_from_address(address=address_in)
    binaddr_hxstr = binaddr_hxstr_from_pubkeyhash_hxstr(pubkeyhash_hxstr=pkh_hxstr)
    address_out = address_from_binaddr_hxstr(binaddr_hxstr=binaddr_hxstr)

    print("Check: {}".format(address_in == address_out))
    '''
