from IntegerValidation import ValidateString as VaSt


def validate_list_entries_numeralsystem(list_in: list,
                                        num_sys: int,
                                        max_value: int = 0):
    """=== Function name: validate_list_entries_numeralsystem ==========================================================
    Function checks list for numeral system related usecases.
    In order to be valid, list items MUST be convertible into integers of the chosen numeral system.
    1.) by default zero value is assumed to be used, so digits MUST be between 0 and num-sys - 1
    :param list_in: list - to be validated
    :param num_sys: system items must be valid members of.
    :param max_value: if given, item value must be below it.
    :return: bool: True if list is valid, False if it contains any invalid items
    ============================================================================================== by Sziller ==="""

    err_msg_maxvalue = "     at least one value entered exceeds value limit: (x < %s)" % max_value
    err_msg_numsys = "     at least one digit entered exceeds numeral system limit: (d < %s)" % num_sys
    for item in list_in:
        try:
            value = int(str(item), num_sys)
        except ValueError as e:
            # raise Exception(err_msg_numsys.format(e)) from None
            print(err_msg_numsys)
            return False
        if max_value:
            if value > max_value:
                print(err_msg_maxvalue)
                return False
    return True


def validate_list_length(list_in: list, length_list=[1, 32], *args, **kwargs):
    """=== Function name: validate_list_length =========================================================================

    :param list_in:
    :param length_list:
    :return:
    ============================================================================================== by Sziller ==="""
    err_msg_length = "     unexpected length of hexadecimal key!"
    if len(list_in) in length_list:
        return True
    else:
        print(err_msg_length)
        return False


def validate_list_entries_length(list_in: list, entry_length_to_check: int = 2, *args, **kwargs):
    """=== Function name: validate_list_entries_length =================================================================

    :param list_in:
    :param entry_length_to_check:
    :param args:
    :param kwargs:
    :return:
    ============================================================================================== by Sziller ==="""
    err_msg_length = "     at least one list entry's length does not match the assumtion (%s)" % entry_length_to_check
    for _ in list_in:
        if len(_) != entry_length_to_check:
            raise Exception(err_msg_length)
    return True


def validate_list_entries_type(list_in: list, type_to_check: type = str, *args, **kwargs):
    """=== Function name: validate_list_entries_type ===================================================================

    :param list_in:
    :param type_to_check:
    :return:
    ============================================================================================== by Sziller ==="""
    valid = True
    for item in list_in:
        valid = valid and isinstance(item, type_to_check)
        if not valid: break
    return valid


def validate_list_entries_all_in_referencelist(list_in: list, reference_list: list):
    """=== Function name: validate_list_entries_all_in_referencelist ===================================================
    Function checks if ALL of list_in's entries can be found in reference_list.
    :param list_in:
    :param reference_list:
    :return:
    ============================================================================================== by Sziller ==="""
    err_msg = "     at least one of lists entries isn't included in reference list."
    if not all(elem in reference_list for elem in list_in):
        print(err_msg)
        return False
    return True


def validate_list_entries_any_in_referencelist(list_in: list, reference_list: list):
    """=== Function name: validate_list_entries_all_in_referencelist ===================================================
        Function checks if ANY - at least one - of list_in's entries can be found in reference_list.
        :param list_in:
        :param reference_list:
        :return:
        ============================================================================================== by Sziller ==="""
    return any(elem in reference_list for elem in list_in)


def validate_list_entries_convertible_to_decimal(list_in: list):
    """=== Function name: validate_list_entries_convertible_to_decimal =================================================
        Function checks if list members can be converted into decimal values.
        :param list_in:
        :return:
        ========================================================================================== by Sziller ==="""
    err_msg_decimal = "     at least one entry cannot be converted into a decimal value"
    for entry in list_in:
        try:
            int(entry)
        except ValueError:
            print(err_msg_decimal)
            return False
    return True


def validate_list_for_nonzero(list_in: list, num_sys: int = 6, zero_used: bool = True) -> bool:
    """=== Function name: validate_list_for_nonzero ================================================================
        Checking if input will not be interpretted as zero. For zero use, any number of 000-s are considered zero,
        for No Zero use a value is considered zero if - for a base of x characters (3 for 256) the last x characters of
        the value equal the base:
        . 1124256 is considered zero for base 256 (if no zero use).
        . 0016 is considered zero for base 16 (if no zero use).
        :param list_in: list of incoming characters. (considered to be made up of integers
        :param num_sys: integer - the base of the numeral system.
        :param zero_used: bool - if zero characters are used. If False, the highest char (the base) is considered zero.
        :return:
        ========================================================================================== by Sziller ==="""
    if zero_used:
        boollist = [all([c == '0' for c in str(_)]) for _ in list_in]
    else:
        boollist = [str(_)[- len(str(num_sys)):] == str(num_sys) for _ in list_in]
    return not all(boollist)


def validate_list_entries_for_num_sys(list_in: list, num_sys: int = 6, zero_used: bool = True) -> bool:
    """=== Function name: validate_list_entries_for_num_sys ========================================================
    Validating if list members are:
    - integers
    - useable in the entered numeral system
    - not larger than max value allowed
    - if shifted by not allowing zero use
    :param list_in:
    :param num_sys:
    :param zero_used:
    :return:
    ========================================================================================== by Sziller ==="""

    err_msg_numsys = "     at least one integer entered exceeds numeral system limit:\n" \
                     "     o   0 <= I <  %s      if zero       allowed\n" \
                     "     o   0 <  I <= %s      if zero isn't allowed" % (num_sys, num_sys)

    for integer in list_in:
        if (zero_used and not (0 <= integer < num_sys)) or (not zero_used and not (0 < integer <= num_sys)):
            print(err_msg_numsys)
            return False
    return True


def validate_list_entries_base58(list_in: list):
    """=== Function name: validate_list_entries_base58 =================================================================
    Checks if all entries in given list only contain base58 characters.
    Usecase Bitcoin addresses MUST be in base58
    :param list_in:
    :return:
    """
    err_masg = "     at least one character you entered isn't included in the Base58 character set!"
    for entries in list_in:
        if not VaSt.validate_base58_string(string_in=entries):
            print(err_masg)
            return False
    return True


def validate_list_entries_range(list_in: list, cap: int = 1):
    """=== Function name: validate_list_entries_range ==================================================================
    Checks if entries are:
    - non negative integers
    - below or equal cap
    ATTENTION! floats are NOT rounded to integers but return FALSE
    ============================================================================================== by Sziller ==="""
    err_msg_notint = "     at least one entry cannot be turned into an integer."
    err_msg_outlim = "     at least one of the numbers entered does not refer to a utxo."

    for integer in list_in:
        try:
            if not 0 <= int(integer) <= cap:
                print(err_msg_outlim)
                return False
        except ValueError:
            print(err_msg_notint)
            return False
    return True


def validate_if_entries_unique(list_in: list):
    """=== Function name: validate_if_entries_unique ===================================================================
    Checks if list enrties are unique. Returns True if every entry is unique, otherwise False.
    ATTENTION!  Booleans are interpretted in a flexible way: True == 1, False == 0
                Is there a 1 and a True in a list, only one of them makes it into the set
                None value seems to be unique in this regard. It does not have a numerical substitute.
    ============================================================================================== by Sziller ==="""
    err_msg_notunq = "     at least one entry was entered more than once."
    err_msg_typeer = "Cannot have <list> or <dict> type entries in list for uniqueness validation\n" \
                     "sais validate_if_entries_unique() at ValidateList.py"
    try:
        if len(list_in) != len(set(list_in)):
            print(err_msg_notunq)
            return False
        else:
            return True
    except TypeError:
        raise Exception(err_msg_typeer) from None


if __name__ == "__main__":
    '''-----------------------------------------------------------------------
    - validate_list_entries_all_in_referencelist                       START -
    - validate_list_entries_any_in_referencelist                       START -
    -----------------------------------------------------------------------'''
    # base_list = [3, 5]
    # base_list = [1, 2, 4, 8]
    # ref_list = [1, 3, 5, 7, 9, 11, 13]
    # print(validate_list_entries_all_in_referencelist.__doc__)
    # print(validate_list_entries_all_in_referencelist(list_in=base_list, reference_list=ref_list))

    # print(validate_list_entries_any_in_referencelist.__doc__)
    # print(validate_list_entries_any_in_referencelist(list_in=base_list, reference_list=ref_list))
    '''-----------------------------------------------------------------------
    - validate_list_entries_all_in_referencelist                       ENDED -
    - validate_list_entries_any_in_referencelist                       ENDED -
    -----------------------------------------------------------------------'''

    '''-----------------------------------------------------------------------
    - validate_list_entries_numeralsystem                              START -
    -----------------------------------------------------------------------'''
    # stringrange = ['11', '01', '3', 'f3', 'aa', 'e7', '7f', 'ff', '00']
    # stringrange = ['1', '5', '1', '3', '5', '1', '6', '2', 2, '7', '2', '5', '5']
    # # stringrange = ['11', '01', '00', '1', '0', '0', '1', '10', '00']
    # # stringrange = ['11', '01', '111', '1', '10', '02']
    # stringrange = ['01', 'ad', '17', 'ff', '3e']
    # print(validate_list_entries_numeralsystem(list_in=stringrange, num_sys=16, max_value=255))
    '''-----------------------------------------------------------------------
    - validate_list_entries_numeralsystem                              ENDED -
    -----------------------------------------------------------------------'''

    '''-----------------------------------------------------------------------
    - validate_list_entries_type                                       START -
    -----------------------------------------------------------------------'''
    # stringrange = ['11', '01', '3', 'f3', '2', 'e7', '7f', 'ff', '00']
    # print(validate_list_entries_type(list_in=stringrange, type_to_check=str))
    '''-----------------------------------------------------------------------
    - validate_list_entries_type                                       ENDED -
    -----------------------------------------------------------------------'''

    '''-----------------------------------------------------------------------
    - validate_list_for_nonzero                                        START -
    -----------------------------------------------------------------------'''
    # stringrange = ['2', '2', '00002']
    # print(validate_list_for_nonzero(list_in=stringrange, num_sys=2, zero_used=False))
    '''-----------------------------------------------------------------------
    - validate_list_for_nonzero                                        ENDED -
    -----------------------------------------------------------------------'''

    '''-----------------------------------------------------------------------
    - validate_list_entries_convertible_to_decimal                     START -
    -----------------------------------------------------------------------'''
    stringrange = [1, 23, False]
    print(validate_list_entries_convertible_to_decimal(list_in=stringrange))
    '''-----------------------------------------------------------------------
    - validate_list_entries_convertible_to_decimal                     ENDED -
    -----------------------------------------------------------------------'''