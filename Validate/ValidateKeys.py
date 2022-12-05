from IntegerValidation import ValidateString as VaSt
from CryptographyApplied import CustomMadeCryptography as CMCy
import codecs
import base58


def validate_prvkey_wif(prvkey_wif: str, *args, **kwargs) -> bool:
    """=== Function name: validate_prvkey_wif ==========================================================================

    :param prvkey_wif:
    :return:
    """
    bytecount = 4
    if VaSt.validate_base58_string(string_in=prvkey_wif):
        reverted__bytes = codecs.encode((base58.b58decode(bytes(prvkey_wif, "ascii"))), "hex")
        reverted_hxstr = (bytes.decode(reverted__bytes))
        hxstr_no_checksum = reverted_hxstr[:bytecount * -2]
        checksum_read = CMCy.read_checksum_x_byte_hxstr(hxstr=reverted_hxstr, bytecount=4, front=False)
        checksum_calc = CMCy.create_checksum_x_byte_hxstr(hxstr=hxstr_no_checksum, bytecount=4, front=True)
        if checksum_calc == checksum_read:
            return True
        else:
            return False
    else:
        return False


def validate_prvkey_hxstr(prvkey_hxstr: str) -> bool:
    """=== Function name: validate_prvkey_hxstr ========================================================================
    Checks if entered hex-string can be interpretted as a valid private key for the Bitcoin system.
    :param prvkey_hxstr: string
    :return:
    ============================================================================================== by Sziller ==="""
    if VaSt.validate_hexstring(string_in=prvkey_hxstr) and len(prvkey_hxstr) == 64:
        return True
    else:
        return False


if __name__ == "__main__":
    print(validate_prvkey_wif.__doc__)
    _wif = "Kxo6cNBGgZciDAFL6cGvz7qNJaBezt3jPEWqHn56fbJKzBJXWw21"
    print(validate_prvkey_wif(prvkey_wif=_wif))
