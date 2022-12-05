import sys

if __name__ == "__main__":
    logical_table = {'false': False, 'no': False, 'n': False, 'nil': False, 'not': False, 'nope': False,
                     'nay': False, 'true': True, 'yes': True, 'y': True, 't': True, 'yep': True,
                     'yepp': True, 'aye': True, 'yea': True, 'yeah': True}
    try:
        # When starting from icon:
        bool_in = logical_table[str(sys.argv[1]).lower()]
        print("--- Initiated by ICONCLICK ---")
        # ------------------------------------------------------
    except IndexError:
        # When starting from IDLE:
        bool_in = False
        print("--- Initiated over IDLE ---")
        # ------------------------------------------------------
    __bbbb = {'iconstart': bool_in}  # testentry
    print("<App_SalletVisor.py> - started")
    input("Push ENTER to start!")
    # (**__bbbb)  # problem code
