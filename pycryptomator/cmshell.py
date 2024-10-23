import cmd, sys, os, glob
from os.path import *
from .cryptomator import *

if os.name == 'nt':
    from .w32lex import split, join # shlex ban \ in pathnames!
else:
    from shlex import split, join


class Options:
    pass

class CMShell(cmd.Cmd):
    intro = 'PyCryptomator Shell.  Type help or ? to list all available commands.'
    prompt = 'PCM:> '
    vault = None

    def __init__ (p, vault):
        p.vault = vault
        super(CMShell, p).__init__()

    def preloop(p):
        p.prompt = '%s:> ' % p.vault.base

    def precmd(p, line):
        #~ print('debug: cmdline=', line)
        # shell wildcards expansion
        argl = []
        for arg in split(line):
            if '?' in arg or '*' in arg:
                if argl[0] == 'encrypt':
                    argl += glob.glob(arg) # probably, we want globbing "real" pathnames
                else:
                    argl += p.vault.glob(arg)
            else:
                argl += [arg]
        line = join(argl)
        #~ print('debug: final cmdline=', line)
        return line

    def do_quit(p, arg):
        'Quit the PyCryptomator Shell'
        sys.exit(0)

    def do_alias(p, arg):
        'Show the real pathname of a virtual file or directory'
        argl = split(arg)
        if not argl:
            print('use: alias <virtual pathname>')
            return
        for it in argl:
            i = p.vault.getInfo(it)
            print(i.realPathName)

    def do_backup(p, arg):
        'Backup all the dir.c9r with their tree structure in a ZIP archive'
        argl = split(arg)
        if not argl:
            print('use: backup <ZIP archive>')
            return
        backupDirIds(p.vault.base, argl[0])
        
    def do_decrypt(p, arg):
        'Decrypt files or directories from the vault'
        argl = split(arg)
        move = '-m' in argl
        if move: argl.remove('-m')
        force = '-f' in argl
        if force: argl.remove('-f')
        if not argl or argl[0] == '-h' or len(argl) < 2:
            print('use: decrypt [-m] [-f] <virtual_pathname_source1...> <real_pathname_destination>')
            print('use: decrypt <virtual_pathname_source> -')
            return
        try:
            for it in argl[:-1]:
                is_dir = p.vault.getInfo(it).isDir
                if is_dir:
                    p.vault.decryptDir(it, argl[-1], force, move)
                else:
                    p.vault.decryptFile(it, argl[-1], force, move)
                    if argl[-1] == '-': print()
        except:
            print(sys.exception())

    def do_encrypt(p, arg):
        'Encrypt files or directories into the vault, eventually moving them'
        argl = split(arg)
        move = '-m' in argl
        if move: argl.remove('-m')
        if not argl or argl[0] == '-h' or len(argl) < 2:
            print('use: encrypt [-m] <real_pathname_source1...> <virtual_pathname_destination>')
            return
        try:
            for it in argl[:-1]:
                if isdir(it):
                    p.vault.encryptDir(it, argl[-1], move=move)
                else:
                    p.vault.encryptFile(it, argl[-1], move=move)
        except:
            print(sys.exception())
            
    def do_ls(p, arg):
        'List files and directories'
        o = Options()
        argl = split(arg)
        o.recursive = '-r' in argl
        if o.recursive: argl.remove('-r')
        o.banner = not '-b' in argl
        if not o.banner: argl.remove('-b')
        o.sorting = None
        if '-s' in argl:
            i = argl.index('-s')
            o.sorting = argl[i+1]
            if not o.sorting:
                print('sorting method not specified')
                return
            for c in o.sorting:
                if c not in 'NSDE-!':
                    print('bad sorting method specified')
                    return
            argl.remove('-s')
            argl.remove(o.sorting)
        if not argl: argl += ['/'] # implicit argument
        if argl[0] == '-h':
            print('use: ls [-b] [-r] [-s NSDE-!] <virtual_path1> [...<virtual_pathN>]')
            return
        try:
            p.vault.ls(argl, o)
        except:
            print(sys.exception())

    def do_ln(p, arg):
        'Make a symbolic link to a file or directory'
        argl = split(arg)
        if len(argl) != 2:
            print('use: ln <target_virtual_pathname> <symbolic_link_virtual_pathname>')
            return
        try:
            p.vault.ln(argl[0], argl[1])
        except:
            print(sys.exception())

    def do_mkdir(p, arg):
        'Make a directory or directory tree'
        argl = split(arg)
        if not argl or argl[0] == '-h':
            print('use: mkdir <dir1> [...<dirN>]')
            return
        for it in argl:
            try:
                p.vault.mkdir(it)
            except:
                print(sys.exception())

    def do_mv(p, arg):
        'Move or rename files or directories'
        argl = split(arg)
        if len(argl) < 2 or argl[0] == '-h':
            print('please use: mv <source> [<source2>...<sourceN>] <destination>')
            return
        for it in argl[:-1]:
            p.vault.mv(it, argl[-1])

    def do_rm(p, arg):
        'Remove files and directories'
        argl = split(arg)
        force = '-f' in argl
        if force: argl.remove('-f')
        if not argl or argl[0] == '-h':
            print('use: rm <file1|dir1> [...<fileN|dirN>]')
            return
        for it in argl:
            if it == '/':
                print("Won't erase root directory.")
                return
            try:
                i = p.vault.getInfo(it)
                if not i.isDir:
                    p.vault.remove(it) # del file
                    continue
                if force:
                    p.vault.rmtree(it) # del dir, even if nonempty
                    continue
                p.vault.rmdir(it) # del empty dir
            except:
                print(sys.exception())
