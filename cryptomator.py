#!/usr/bin/python3

"""

   MIT License

   Copyright (c) 2024 maxpat78

"""

# Requires pycryptodome(x)

import argparse, getpass, hashlib, struct, base64
import json, sys, io, os, operator
import time, zipfile, locale, zlib

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import HMAC, SHA256
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256


class Vault:
    "Handles a Cryptomator vault"
    def __init__ (p, directory, password=None, pk=None, hk=None):
        if not os.path.isdir(directory):
            raise BaseException('A directory pathname must be passed!')
        p.base = directory
        vcs = 'vault.cryptomator'
        config = os.path.join(p.base, vcs)
        try:
            s = open(config,'rb').read()
            assert len(s)
        except:
            raise BaseException('Unaccessible or invalid '+vcs)
        header, payload, sig = s.split(b'.')
        #~ dheader = json.loads(base64.b64decode(header+b'==='))
        #~ dpayload = json.loads(base64.b64decode(payload+b'==='))
        dheader = json.loads(d64(header))
        dpayload = json.loads(d64(payload))
        dsig = d64(sig, 1)
        #~ print('header',dheader,'\n','payload',dpayload)
        assert dheader['typ'] == 'JWT'
        kid = dheader['kid']
        if not kid.startswith('masterkeyfile:'):
            raise BaseException('Invalid kid in '+vcs)
        alg = dheader['alg']
        if alg not in ('HS256','HS384','HS512'):
            raise BaseException('Invalid HMAC algorithms in '+vcs)
        assert dpayload['format'] == 8 # latest Vault format
        assert dpayload['cipherCombo'] == 'SIV_GCM' # AES-GCM with 96-bit IV and 128-bit tag (replaces AES-CTR+HMAC SHA-256)
        mkcs = os.path.join(p.base, kid[14:])
        master = json.load(open(mkcs))
        #~ print('master', master)
        if hk and pk:
            p.pk = pk
            p.hk = hk
        else:
            kek = hashlib.scrypt(password.encode('utf-8'),
                                       salt=d64(master['scryptSalt']),
                                       n=master['scryptCostParam'], r=master['scryptBlockSize'], p=1,
                                       maxmem=0x7fffffff, dklen=32)
            primary_master_key = aes_unwrap(kek, d64(master['primaryMasterKey']))
            hmac_master_key = aes_unwrap(kek, d64(master['hmacMasterKey']))
            h = HMAC.new(primary_master_key+hmac_master_key, header+b'.'+payload, digestmod=SHA256)
            if dsig != h.digest():
                raise BaseException('Invalid HMAC for'+vcs)
            p.pk = primary_master_key
            p.hk = hmac_master_key

    def hashDirId(p, dirId):
        aes = AES.new(p.hk+p.pk, AES.MODE_SIV)
        es, tag = aes.encrypt_and_digest(dirId)
        dirIdE = tag+es
        # encrypted DirId SHA-1 in Base32
        return base64.b32encode(hashlib.sha1(dirIdE).digest()).decode()

    def encryptName(p, dirId, name):
        "Encrypts a name contained in a given directory"
        dirIdE = aes_siv_encrypt(p.pk, p.hk, name, dirId)
        # concatenated 128-bit digest and encrypted name
        return base64.urlsafe_b64encode(dirIdE) + b'.c9r'

    def decryptName(p, dirId, name):
        assert name[-4:] == b'.c9r'
        dname = d64(name[:-4], 1)
        return aes_siv_decrypt(p.pk, p.hk, dname, dirId)

    def getDirId(p, virtualpath):
        "Get the Directory Id related to a virtual path inside the vault"
        dirId = '' 
        parts = virtualpath.split('/')
        for it in parts:
            if not it: continue
            hdid = p.hashDirId(dirId.encode())
            #~ print ('debug: hdid for', dirId, 'is', hdid)
            ename = p.encryptName(dirId.encode(), it.encode())
            #~ print('debug: dir %s -> %s' % (it, ename))
            diridfn = os.path.join(p.base, 'd', hdid[:2], hdid[2:], ename.decode(), 'dir.c9r')
            if not os.path.exists(diridfn):
                raise BaseException('could not find '+virtualpath)
            dirId = open(diridfn).read()
        return dirId

    def getDirPath(p, virtualpath):
        "Get the real pathname of a virtual directory path inside the vault"
        hdid = p.hashDirId(p.getDirId(virtualpath).encode())
        realpath = os.path.join(p.base, 'd', hdid[:2], hdid[2:])
        if not os.path.isdir(realpath):
            raise BaseException('Could not find real directory for "%s" inside vault!'%realpath)
        return realpath
        
    def getFilePath(p, virtualpath):
        "Get the real pathname of a virtual file pathname inside the vault"
        vbase = os.path.dirname(virtualpath)
        vname = os.path.basename(virtualpath)
        realbase = p.getDirPath(vbase)
        dirId = p.getDirId(vbase)
        ename = p.encryptName(dirId.encode(), vname.encode()).decode()
        if len(ename) > 220:
            # SHA-1 hash, Base64 encoded, of the encrypted long name
            shortn = base64.urlsafe_b64encode(hashlib.sha1(ename.encode()).digest()).decode() + '.c9s'
            ename = os.path.join(realbase, shortn, 'contents.c9r')
            if not os.path.exists(ename) and os.path.exists(os.path.join(realbase, shortn, 'dir.c9r')): # if long dir name
                ename = shortn
        target = os.path.join(realbase, ename)
        if not os.path.exists(target):
            raise BaseException(virtualpath+' is not a valid virtual file pathname')
        return target
        
    def listDir(p, virtualpath):
        "List directory contents of a virtual path inside the vault"
        realpath = p.getDirPath(virtualpath)
        dirId = p.getDirId(virtualpath)
        for it in os.scandir(realpath):
            if it.name == 'dirid.c9r': continue
            dname = decryptName(p.pk, p.hk, dirId.encode(), it.name.encode())
            print(dname)

    def decryptFile(p, virtualpath, dest, force=False):
        "Decrypt a file from a virtual pathname and puts it in real 'dest'"
        f = open(p.getFilePath(virtualpath), 'rb')
        
        # Get encrypted header
        h = f.read(68)
        hnonce, hpayload, htag = h[:12], h[12:-16], h[-16:]

        # Get content key
        dh = AES.new(p.pk, AES.MODE_GCM, nonce=hnonce).decrypt_and_verify(hpayload, htag)
        assert dh[:8] == b'\xFF'*8
        key = dh[8:] # 256-bit AES key
        
        # Process contents (AES-GCM encrypted, too)
        if os.path.exists(dest) and not force:
            raise BaseException('destination file "%s" exists and won\'t get overwritten!'%dest)
        out = open(dest, 'wb')
        n = 0
        while True:
            s = f.read(32768+28) # an encrypted block is at most 32K + 28 bytes
            if not s: break
            nonce, payload, tag = s[:12], s[12:-16], s[-16:]
            aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
            aes.update(struct.pack('>Q', n)) # AAD: block number
            aes.update(hnonce) # AAD: header nonce
            try:
                ds = aes.decrypt_and_verify(payload, tag)
            except:
                print("warning: block %d is damaged and won't be decrypted" % n)
                ds = payload
            out.write(ds)
            n += 1
        f.close()
        out.close()
        # restore original last access and modification time
        st = p.stat(virtualpath)
        os.utime(dest, (st.st_atime, st.st_mtime))
        return st.st_size
    
    def decryptDir(p, virtualpath, dest, force=False):
        if (virtualpath[0] != '/'):
            raise BaseException('the vault path to decrypt must be absolute!')
        real = p.getDirPath(virtualpath) # test existance
        n=0
        nn=0
        total_bytes = 0
        T0 = time.time()
        for root, dirs, files in p.walk(virtualpath):
            nn+=1
            for it in files:
                fn = os.path.join(root, it).replace('\\','/')
                dn = os.path.join(dest, fn[1:]) # target pathname
                bn = os.path.dirname(dn) # target base dir
                if not os.path.exists(bn):
                    os.makedirs(bn)
                print(dn)
                total_bytes += p.decryptFile(fn, dn, force)
                n += 1
        T1 = time.time()
        print('decrypting %s bytes in %d files and %d directories took %d seconds' % (_fmt_size(total_bytes), n, nn, T1-T0))

    def stat(p, virtualpath):
        "Perform os.stat on a virtual pathname"
        target = p.getFilePath(virtualpath)
        return os.stat(target)

    def ls(p, virtualpath, recursive=False):
        "Print a list of contents of a virtual path"
        def _realsize(n):
            "Returns the decrypted file size"
            if n == 68: return 0 # header only
            cb = (n - 68 + (32768+28-1)) // (32768+28) # number of encrypted blocks
            return n - 68 - (cb*28)
        for root, dirs, files in p.walk(virtualpath):
            print('\n  Directory of', root, '\n')
            tot_size = 0
            for it in dirs:
                full = os.path.join(root, it).replace('\\','/')
                st = v.stat(full)
                print('%12s  %s  %s' %('<DIR>', time.strftime('%Y-%m-%d %H:%M', time.localtime(st.st_mtime)), it))
            for it in files:
                full = os.path.join(root, it).replace('\\','/')
                st = v.stat(full)
                size = _realsize(st.st_size)
                tot_size += size
                print('%12s  %s  %s' %(_fmt_size(size), time.strftime('%Y-%m-%d %H:%M', time.localtime(st.st_mtime)), it))
            print('\n%s bytes in %d files and %d directories.' % (_fmt_size(tot_size), len(files), len(dirs)))
            if not recursive: break
        
    def walk(p, virtualpath):
        "Traverse the virtual file system like os.walk"
        #~ print('walking in', virtualpath)
        realpath = p.getDirPath(virtualpath)
        dirId = p.getDirId(virtualpath)
        root = virtualpath
        dirs = []
        files = []
        #~ print('virtual', virtualpath, 'is real', realpath)
        for it in os.scandir(realpath):
            if it.name == 'dirid.c9r': continue
            isdir = it.is_dir()
            if it.name.endswith('.c9s'):  # deflated long name
                # A c9s dir contains the original encrypted long name (name.c9s) and encrypted contents (contents.c9r)
                ename = open(os.path.join(realpath, it.name, 'name.c9s')).read()
                dname = p.decryptName(dirId.encode(), ename.encode()).decode()
                if os.path.exists(os.path.join(realpath, it.name, 'contents.c9r')): isdir = False
            else:
                dname = p.decryptName(dirId.encode(), it.name.encode()).decode()
            if isdir: dirs += [dname]
            else: files += [dname]
        yield root, dirs, files
        for it in dirs:
            subdir = os.path.join(root, it).replace('\\','/')
            yield from p.walk(subdir)

# AES utility functions

def aes_unwrap(kek, C):
    "AES key unwrapping according to RFC3394"
    if len(C)%8:
        raise BaseException("full 64 bits blocks required")
    n = len(C)//8 - 1 # 64-bit blocks (key)
    A = bytearray(C[:8]) # crypted IV (start = 0xA6A6A6A6A6A6A6A6)
    R = bytearray(C)
    for j in range(5,-1,-1): # 5..0
        for i in range(n, 0, -1): # n..1
            t = bytearray(struct.pack('>Q', n*j+i)) # Big Endian number
            AxorT = bytearray(map(operator.xor, A, t))
            B = AES.new(kek, AES.MODE_ECB).decrypt(AxorT + R[i*8:i*8+8])
            A = B[:8]
            R[i*8:i*8+8] = B[8:]
    if A != b'\xA6'*8:
        raise BaseException('AES key unwrap failed. Bad password?')
    return R[8:]

def aes_siv_encrypt(pk, hk, s, ad=b''):
    aes = AES.new(hk+pk, AES.MODE_SIV)
    if s: aes.update(ad)
    es, tag = aes.encrypt_and_digest(s)
    return tag+es

def aes_siv_decrypt(pk, hk, s, ad=b''):
    aes = AES.new(hk+pk, AES.MODE_SIV)
    aes.update(ad)
    ds = aes.decrypt_and_verify(s[16:], s[:16])
    return ds

# Other utilities

def d64(s, safe=0):
    D = base64.b64decode
    pad = b'==='
    if safe: D = base64.urlsafe_b64decode
    if type(s) != type(b''): pad = pad.decode()
    return D(s+pad)

def _fmt_size(size):
    "Internal function to format sizes"
    if size >= 10**12:
        sizes = {0:'B', 10:'K',20:'M',30:'G',40:'T',50:'E'}
        k = 0
        for k in sorted(sizes):
            if (size // (1<<k)) < 10**6: break
        size = locale.format_string('%.02f%s', (size/(1<<k), sizes[k]), grouping=1)
    else:
        size = locale.format_string('%d', size, grouping=1)
    return size

# If a DirectoryID file dir.c9r gets lost or corrupted, names in that directory can't be restored!
def backupDirIds(vault_base, zip_backup):
    "Archive in a ZIP file all the DirectoryIDs with their encrypted tree, for backup purposes"
    if not os.path.exists(vault_base) or \
    not os.path.isdir(vault_base) or \
    not os.path.exists(os.path.join(vault_base,'vault.cryptomator')):
        raise BaseException(vault_base+' is not a valid Cryptomator vault directory!')
    zip = zipfile.ZipFile(zip_backup, 'w', zipfile.ZIP_DEFLATED)
    n = len(vault_base)
    df = 'dir.c9r'
    for root, dirs, files in os.walk(vault_base):
        if df in files:
            it = os.path.join(root[n+1:], df) # ZIP item name (relative name)
            s =  os.path.join(vault_base, it) # source file to backup with the plain text directory UUID
            zip.write(s, it)
    zip.close()

class Wordsencoder:
    def __init__(p, dictionary):
        "Initialize a dictionary with 4096 words"
        words = open(dictionary).readlines()
        words = [x for x in map(lambda x: x.strip('\n'), words)]
        if len(words) != 4096: raise BaseException('A 4096 words list is required!')
        p.dictionary = words

    def words2bytes(p, words):
        """Convert a list of words into a bytes sequence. Each word represents 
        12 raw bits and must belong to the 4096-words reference dictionary """
        n = 0
        b = bytearray()
        cb = 0
        for w in words:
            if w not in p.dictionary: raise BaseException('Word "%s" does not belong to dictionary' % w)
            i = p.dictionary.index(w) # get word 12-bit index
            n |= i # or with n
            cb += 1
            if cb == 2: # emit 3 bytes every 24 bits
                b += n.to_bytes(3,'big')
                n = 0
                cb = 0
                continue
            n <<= 12 # shift by 12 bits
        return b

    def bytes2words(p, s):
        """Convert a byte sequence (24-bit padded) into a words list. Each word represents 
        12 raw bits and must belong to the 4096-words reference dictionary"""
        if len(s) % 3: raise BaseException('Bytes sequence length must be 24-bit multiple!')
        words = []
        for g in [s[i:i+3] for i in range(0, len(s), 3)]: # group by 3 bytes
            n = int.from_bytes(g, 'big')
            i0 = n & 0xFFF
            i1 = (n & 0xFFF000) >> 12
            words += [p.dictionary[i1]]
            words += [p.dictionary[i0]]
        return words

    def blob(p, pk, hk):
        "Get a blob containing the Primary master key (32 bytes), the HMAC key (32 bytes) and a 16-bit checksum"
        b = pk+hk
        return b + p.crc(b)

    def validate(p, s):
        "Ensure the retrieved bytes sequence is a valid Cryptomator key"
        if len(s) != 66:  raise BaseException('Decoded master keys must be 512 bits long with 16-bit checksum!' % w)
        crc = zlib.crc32(s[:64])
        if crc.to_bytes(4,'little')[:2] != s[64:]:
            raise BaseException('Bad master keys checksum!')

    def crc(p, s):
        "Get the 16-bit checksum for the Cryptomator master keys"
        if len(s) != 64:  raise BaseException('Decoded master keys must be 512 bits long!')
        crc = zlib.crc32(s)
        return crc.to_bytes(4,'little')[:2]



if __name__ == '__main__':
    locale.setlocale(locale.LC_ALL, '')

    parser = argparse.ArgumentParser(description="List and decrypt files in a Cryptomator vault")
    parser.add_argument('--print-keys', help="Print the raw master keys in ASCII85 (a85) or BASE64 (b64) format, or as a list of English words for Cryptomator", type=str, choices=['a85','b64','words'])
    parser.add_argument('--master-keys', nargs=2, metavar=('PRIMARY_KEY', 'HMAC_KEY'), help="Primary and HMAC master keys in ASCII85 or BASE64 format, or - - to read words list from standard input")
    parser.add_argument('--password', help="Password to unlock master keys stored in config file")
    parser.add_argument('dirname', help="Location of the vault to open")
    args, extras = parser.parse_known_args()

    if not args.password and not args.master_keys:
        args.password = getpass.getpass()

    if args.master_keys:
        if args.master_keys[0] == '-':
            words = input('Words list: ')
            words = words.split()
            if len(words) != 44: raise BaseException('Not enough words')
            we = Wordsencoder(os.path.join(os.path.dirname(sys.argv[0]), '4096words_en.txt'))
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
        v = Vault(args.dirname, pk=pk, hk=hk)
    else:
        v = Vault(args.dirname, args.password)

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
            we = Wordsencoder(os.path.join(os.path.dirname(sys.argv[0]), '4096words_en.txt'))
            words = we.bytes2words(we.blob(v.pk, v.hk))
            print(' '.join(words))
            sys.exit(0)
        print('Primary master key :', encoder(v.pk).decode())
        print('HMAC master key    :', encoder(v.hk).decode())
        sys.exit(0)

    if not extras:
        print('An operation must be specified among alias, backup, decrypt, ls')
        sys.exit(1)

    if extras[0] == 'alias':
        if len(extras) == 1:
            print('please use: alias <virtual_pathname>')
            sys.exit(1)
        print('"%s" is the real pathname for %s' % (v.getFilePath(extras[1]), extras[1]))
    elif extras[0] == 'backup':
        if len(extras) == 1:
            print('please use: backup <ZIP archive>')
            sys.exit(1)
        backupDirIds(v.base, extras[1])
        print('done.')
    elif extras[0] == 'ls':
        recursive = '-r' in extras
        if recursive: extras.remove('-r')
        if len(extras) == 1:
            print('please use: ls [-r] <virtual_path1> [...<virtual_pathN>]')
            print('(hint: try "ls /" at first)')
            sys.exit(1)
        for it in extras[1:]:
            v.ls(it, recursive)
    elif extras[0] == 'decrypt':
        force = '-f' in extras
        if force: extras.remove('-f')
        if len(extras) != 3:
            print('please use: decrypt [-f] <virtual_pathname_source> <real_pathname_destination>')
            sys.exit(1)
        isdir = 0
        try:
            v.getDirPath(extras[1])
            isdir = 1
        except: pass
        if isdir: v.decryptDir(extras[1], extras[2], force)
        else:
            v.decryptFile(extras[1], extras[2], force)
            print('done.')
    else:
        print('Unknown operation:', extras[0])
        sys.exit(1)
