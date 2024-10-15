import cmd, sys, os
from os.path import *
from .cryptomator import *

if os.name == 'nt':
    from .w32lex import split # shlex ban \ in pathnames!
else:
    from shlex import split

class CMShell(cmd.Cmd):
    intro = 'PyCryptomator Shell.  Type help or ? to list all available commands.'
    prompt = 'PCM:> '
    vault = None

    def __init__ (p, vault):
        p.vault = vault
        super(CMShell, p).__init__()

    def preloop(p):
        p.prompt = '%s:> ' % p.vault.base

    def do_debug(p, arg):
        pass

    def do_quit(p, arg):
        'Quit the PyCryptomator Shell'
        sys.exit(0)

    def do_alias(p, arg):
        'Show the real pathname of a virtual file or directory'
        argl = split(arg)
        if not argl:
            print('use: alias <virtual pathname>')
            return
        i = p.vault.getInfo(argl[0])
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
        force = '-f' in argl
        if force: argl.remove('-f')
        if not argl or argl[0] == '-h' or len(argl) != 2:
            print('use: decrypt [-f] <virtual_pathname_source> <real_pathname_destination>')
            print('use: decrypt <virtual_pathname_source> -')
            return
        try:
            is_dir = p.vault.getInfo(argl[0]).isDir
            if is_dir: p.vault.decryptDir(argl[0], argl[1], force)
            else:
                p.vault.decryptFile(argl[0], argl[1], force)
                if argl[1] == '-': print()
        except:
            print(sys.exception())

    def do_encrypt(p, arg):
        'Encrypt files or directories into the vault, eventually moving them'
        argl = split(arg)
        move = '-m' in argl
        if move: argl.remove('-m')
        if not argl or argl[0] == '-h' or len(argl) != 2:
            print('use: encrypt [-m] <real_pathname_source> <virtual_pathname_destination>')
            return
        try:
            if isdir(argl[0]):
                p.vault.encryptDir(argl[0], argl[1], move=move)
            else:
                p.vault.encryptFile(argl[0], argl[1], move=move)
        except:
            print(sys.exception())
            
    def do_ls(p, arg):
        'List files and directories'
        argl = split(arg)
        recursive = '-r' in argl
        if recursive: argl.remove('-r')
        if not argl: argl += ['/'] # implicit argument
        if argl[0] == '-h':
            print('use: ls [-r] <virtual_path1> [...<virtual_pathN>]')
            return
        for it in argl:
            try:
                p.vault.ls(it, recursive)
            except:
                pass
        
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
