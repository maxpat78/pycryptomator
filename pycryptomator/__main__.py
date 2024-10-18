import locale, sys, argparse
from os.path import *
from .cryptomator import *
from .cmshell import CMShell
from .wordscodec import Wordscodec
if os.name == 'nt':
    import pycryptomator.w32lex as shlex # default shlex ban \ in pathnames!
else:
    import shlex

"""

   MIT License

   Copyright (c) 2024 maxpat78

"""

locale.setlocale(locale.LC_ALL, '')

parser = argparse.ArgumentParser(prog='pycryptomator', description="Access to a Cryptomator V8 vault")
parser.add_argument('--init', action="store_true", help="Initialize a new vault in an empty directory")
parser.add_argument('--print-keys', help="Print the raw master keys as a list of English words for Cryptomator (default), in ASCII85 (a85) or BASE64 (b64) format", type=str, choices=['a85','b64','words'], const='words', nargs='?')
parser.add_argument('--master-keys', nargs=2, metavar=('PRIMARY_KEY', 'HMAC_KEY'), help="Primary and HMAC master keys in ASCII85 or BASE64 format, or - - to read a words list from standard input")
parser.add_argument('--password', help="Password to unlock master keys stored in config file")
parser.add_argument('--change-password', help="Change the password required to open the vault", action="store_true")
parser.add_argument('vault_name', help="Location of the existing Cryptomator V8 vault to use")
args, extras = parser.parse_known_args()

if args.init:
    init_vault(args.vault_name, args.password)
    sys.exit(0)

if not exists(args.vault_name):
    print('Specified vault does not exist:', args.vault_name)
    sys.exit(1)

if not args.password and not args.master_keys:
    args.password = getpass.getpass()

if args.master_keys:
    if args.master_keys[0] == '-':
        words = input('Words list: ')
        words = words.split()
        if len(words) != 44: raise BaseException('Not enough words')
        we = Wordscodec(join(dirname(sys.argv[0]), '4096words_en.txt'))
        b = we.words2bytes(words)
        we.validate(b)
        pk = b[:32]
        hk = b[32:64]
        print()
    else:
        def tryDecode(s):
            e = 0
            d = b''
            try: d = base64.a85decode(s)
            except: pass
            if len(d) == 32: return d
            try: d = base64.urlsafe_b64decode(s)
            except: pass
            if len(d) == 32: return d
            raise BaseException('Could not decode master key "%s"'%s)
        pk = tryDecode(args.master_keys[0])
        hk = tryDecode(args.master_keys[1])
    v = Vault(args.vault_name, pk=pk, hk=hk)
else:
    v = Vault(args.vault_name, args.password)

if args.print_keys:
    print('\n   * * *  WARNING !!!  * * *\n')
    print('KEEP THESE KEYS TOP SECRET!\nFor recovering purposes only.\n')

    if args.print_keys == 'a85':
        encoder = base64.a85encode
    elif args.print_keys == 'b64':
        encoder = base64.urlsafe_b64encode
    else:
        # initialize the words encoder with a dictionary in the same directory
        # it contains 4096 English words
        we = Wordscodec(join(dirname(sys.argv[0]), '4096words_en.txt'))
        words = we.bytes2words(we.blob(v.pk, v.hk))
        print(' '.join(words))
        sys.exit(0)
    print('Primary master key :', encoder(v.pk).decode())
    print('HMAC master key    :', encoder(v.hk).decode())
    sys.exit(0)

if args.change_password:
    v.change_password()
    sys.exit(0)

if not extras:
    CMShell(v).cmdloop() # start a shell with open vault
else:
    # We must re-quote args, shlex should suffice
    CMShell(v).onecmd(shlex.join(extras)) # execute single command via shell
