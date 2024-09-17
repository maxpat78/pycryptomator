#!/usr/bin/python3

"""

   MIT License

   Copyright (c) 2024 maxpat78

"""

# Requires pycryptodome(x)

import argparse, getpass, hashlib, struct, base64
import json, sys, io, os, operator
import time, zipfile, locale, zlib, uuid

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import HMAC, SHA256
    from Cryptodome.Random import get_random_bytes
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256
    from Crypto.Random import get_random_bytes


class Vault:
    "Handles a Cryptomator vault"
    def __init__ (p, directory, password=None, pk=None, hk=None):
        if not os.path.exists(directory):
            raise BaseException('Vault directory does not exist!')
        if not os.path.isdir(directory):
            raise BaseException('Not a directory: '+directory)
        p.base = directory # store vault base directory
        vcs = 'vault.cryptomator'
        config = os.path.join(p.base, vcs)
        try:
            s = open(config,'rb').read()
            assert len(s)
        except:
            raise BaseException('Unaccessible or invalid '+vcs)
        header, payload, sig = s.split(b'.')
        dheader = json.loads(d64(header))
        dpayload = json.loads(d64(payload))
        dsig = d64(sig, 1)
        assert dheader['typ'] == 'JWT'
        kid = dheader['kid']
        if not kid.startswith('masterkeyfile:'):
            raise BaseException('Invalid kid in '+vcs)
        alg = dheader['alg']
        if alg not in ('HS256','HS384','HS512'):
            raise BaseException('Invalid HMAC algorithms in '+vcs)
        assert dpayload['format'] == 8 # latest Vault format
        assert dpayload['cipherCombo'] == 'SIV_GCM' # AES-GCM with 96-bit IV and 128-bit tag (replaces AES-CTR+HMAC SHA-256)
        p.shorteningThreshold = dpayload.get('shorteningThreshold')
        if not p.shorteningThreshold: p.shorteningThreshold = 220 # threshold to encode long names
        p.master_path = os.path.join(p.base, kid[14:]) # masterkey.cryptomator path
        master = json.load(open(p.master_path))
        if not hk or not pk:
            kek = hashlib.scrypt(password.encode('utf-8'),
                                       salt=d64(master['scryptSalt']),
                                       n=master['scryptCostParam'], r=master['scryptBlockSize'], p=1,
                                       maxmem=0x7fffffff, dklen=32)
            pk = aes_unwrap(kek, d64(master['primaryMasterKey']))
            hk = aes_unwrap(kek, d64(master['hmacMasterKey']))
            # check their combined HMAC-SHA-256 with both keys
            h = HMAC.new(pk+hk, header+b'.'+payload, digestmod=SHA256)
            if dsig != h.digest(): raise BaseException('Master keys HMAC do not match!')
            # get the HMAC-SHA-256 of the version number (as 32-bit Big Endian) using the HMAC key only
            h = HMAC.new(hk, int(master['version']).to_bytes(4, 'big'), digestmod=SHA256)
            if master['versionMac'] != base64.b64encode(h.digest()).decode(): raise BaseException('Bad versionMac in masterkey file!')
        p.master = master # store masterkey.cryptomator
        p.pk = pk
        p.hk = hk
        # check for encrypted root presence
        aes = AES.new(hk+pk, AES.MODE_SIV)
        e, tag = aes.encrypt_and_digest(b'') # unencrypted root directory ID is always empty
        # encrypted root directory ID SHA-1, Base32 encoded
        edid = base64.b32encode(hashlib.sha1(tag+e).digest()).decode()
        p.root = os.path.join(p.base, 'd', edid[:2], edid[2:]) # store encrypted root directory
        if not os.path.exists(p.root):
            raise BaseException("Fatal error, couldn't find vault's encrypted root directorty!")
        p.dirid_cache = {} # cache retrieved directory IDs

    def change_password(p):
        "Change the vault password, replacing the masterkey.cryptomator"
        password = ask_new_password()
        scryptSalt = get_random_bytes(8) # new random 64-bit salt
        p.master['scryptSalt'] = base64.b64encode(scryptSalt).decode()
        # calculate the new kek and wrap the master keys
        kek = hashlib.scrypt(password.encode('utf-8'),
                                   salt=scryptSalt,
                                   n=p.master['scryptCostParam'], r=p.master['scryptBlockSize'], p=1,
                                   maxmem=0x7fffffff, dklen=32)
        pk = aes_wrap(kek, p.pk)
        hk = aes_wrap(kek, p.hk)
        # replace the keys in masterkey.cryptomator
        p.master['primaryMasterKey'] = base64.b64encode(pk).decode()
        p.master['hmacMasterKey'] = base64.b64encode(hk).decode()
        # write the new file
        s = json.dumps(p.master)
        open(p.master_path,'w').write(s)
        print('done.')

    def hashDirId(p, dirId):
        "Get the Base32 encoded SHA-1 hash of an encrypted directory id as a string"
        aes = AES.new(p.hk+p.pk, AES.MODE_SIV)
        es, tag = aes.encrypt_and_digest(dirId)
        dirIdE = tag+es
        return base64.b32encode(hashlib.sha1(dirIdE).digest()).decode()

    def encryptName(p, dirId, name):
        "Encrypt a name contained in a given directory"
        dirIdE = aes_siv_encrypt(p.pk, p.hk, name, dirId)
        # concatenated 128-bit digest and encrypted name
        return base64.urlsafe_b64encode(dirIdE) + b'.c9r'

    def decryptName(p, dirId, name):
        "Decrypt a .c9r name"
        assert name[-4:] == b'.c9r'
        dname = d64(name[:-4], 1)
        return aes_siv_decrypt(p.pk, p.hk, dname, dirId)

    def getDirId(p, virtualpath, create=False):
        "Get the Directory Id related to a virtual path inside the vault"
        dirId = '' # root id is null
        parts = virtualpath.split('/')
        for it in parts:
            if not it: continue
            # build the encrypted dir name
            hdid = p.hashDirId(dirId.encode())
            ename = p.encryptName(dirId.encode(), it.encode())
            if len(ename) > p.shorteningThreshold:
                # SHA-1 hash, Base64 encoded, of the encrypted long name
                shortn = base64.urlsafe_b64encode(hashlib.sha1(ename).digest()).decode() + '.c9s'
                c9sdir = os.path.join(p.base, 'd', hdid[:2], hdid[2:], shortn)
                if create and not os.path.exists(c9sdir):
                    # create the .c9s dir and store the long name in name.c9s
                    os.mkdir(c9sdir)
                    open(os.path.join(c9sdir, 'name.c9s'), 'wb').write(ename)
                diridfn = os.path.join(c9sdir, 'dir.c9r')
            else:
                diridfn = os.path.join(p.base, 'd', hdid[:2], hdid[2:], ename.decode(), 'dir.c9r')
            dirId = p.dirid_cache.get(diridfn) # try to retrieve dirId from cache
            if dirId: continue
            if not os.path.exists(diridfn):
                if not create: raise BaseException('could not find '+virtualpath)
                # create the directory encrypted name inside its root
                if not os.path.exists(os.path.dirname(diridfn)): os.makedirs(os.path.dirname(diridfn))
                # create and store a random 36-bytes UUID string for it
                # it is required to: 1) build the name of the associated "real" (=contents) directory;
                # 2) crypt the names inside
                dirId = str(uuid.uuid4()).encode()
                open(diridfn,'wb').write(dirId)
                # make the associated directory and store a backup copy of the dirId
                hdid2 = p.hashDirId(dirId)
                rp2 = os.path.join(p.base, 'd', hdid2[:2], hdid2[2:])
                os.makedirs(rp2)
                backup = os.path.join(rp2, 'dirid.c9r')
                p.encryptFile(io.BytesIO(dirId), backup)
                dirId = dirId.decode() # prepare a str for return
            else:
                dirId = open(diridfn).read()
            p.dirid_cache[diridfn] = dirId # cache directory id
        return dirId

    def getDirPath(p, virtualpath, create=False):
        "Get the real pathname of a virtual directory path inside the vault"
        dirId = p.getDirId(virtualpath, create)
        hdid = p.hashDirId(dirId.encode())
        rp = os.path.join(p.base, 'd', hdid[:2], hdid[2:])
        if not os.path.isdir(rp):
            raise BaseException('Could not find real directory for "%s" inside vault!'%rp)
        return rp
        
    def getFilePath(p, virtualpath, create=False):
        "Get the real pathname of a virtual file pathname inside the vault"
        vbase = os.path.dirname(virtualpath)
        vname = os.path.basename(virtualpath)
        realbase = p.getDirPath(vbase)
        if vname == 'dirid.c9r': # special backup directory id file
            return os.path.join(realbase, 'dirid.c9r')
        dirId = p.getDirId(vbase)
        ename = p.encryptName(dirId.encode(), vname.encode()).decode()
        if len(ename) > p.shorteningThreshold:
            # SHA-1 hash, Base64 encoded, of the encrypted long name
            shortn = base64.urlsafe_b64encode(hashlib.sha1(ename.encode()).digest()).decode() + '.c9s'
            contents_c9r = os.path.join(realbase, shortn, 'contents.c9r')
            if create:
                os.mkdir(os.path.dirname(contents_c9r))
                open(contents_c9r,'w').close()
                namef = os.path.join(realbase, shortn, 'name.c9s')
                open(namef,'w').write(ename)
                return contents_c9r
            else:
                ename = contents_c9r[len(realbase)+1:]
                if not os.path.exists(contents_c9r) and os.path.exists(os.path.join(realbase, shortn, 'dir.c9r')): # if long dir name
                    ename = shortn
        target = os.path.join(realbase, ename)
        if not create and not os.path.exists(target):
            raise BaseException(virtualpath+' is not a valid virtual file pathname')
        return target
        
    def encryptFile(p, src, virtualpath, force=False):
        "Encrypt a 'src' file into a pre-existant vault's virtual pathname (or a file-like object into a real path)"
        if hasattr(src, 'read'): # if it's file
            f = src
        else:
            if not os.path.exists(src):
                raise BaseException('Source file does not exist: '+src)
            f = open(src, 'rb')
        if not os.path.basename(virtualpath).endswith('dirid.c9r'):
            if not p.getDirPath(os.path.dirname(virtualpath)):
                raise BaseException('Target directory does not exist: '+os.path.dirname(virtualpath))
            rp = p.getFilePath(virtualpath, 1)
        else:
            rp = virtualpath
        out = open(rp,'wb')
        hnonce = get_random_bytes(12) # random 96-bit header nonce
        key = get_random_bytes(32) # random 256-bit content encryption key
        payload = bytearray(b'\xFF'*8 + key)
        epayload, tag = AES.new(p.pk, AES.MODE_GCM, nonce=hnonce).encrypt_and_digest(payload)
        # write 68 byte header: nonce, encrypted key and tag
        out.write(hnonce)
        out.write(epayload)
        out.write(tag)
        # encrypt single blocks
        n = 0
        while True:
            s = f.read(32768) # a plaintext block is at most 32K
            if not s: break
            nonce = get_random_bytes(12) # random 96-bit nonce
            aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
            aes.update(struct.pack('>Q', n)) # AAD: 64-bit block number
            aes.update(hnonce) # AAD: header nonce
            es, tag = aes.encrypt_and_digest(s)
            # write block nonce, payload and tag
            out.write(nonce)
            out.write(es)
            out.write(tag)
            n += 1
        cb = out.tell()
        out.close()
        f.close()
        if not hasattr(src, 'read'):
            st = os.stat(src)
            os.utime(out.name, (st.st_atime, st.st_mtime))
        return cb

    def encryptDir(p, src, virtualpath, force=False):
        if (virtualpath[0] != '/'):
            raise BaseException('the vault path must be absolute!')
        real = p.getDirPath(virtualpath, 1)
        n=0
        nn=0
        total_bytes = 0
        T0 = time.time()
        for root, dirs, files in os.walk(src):
            nn+=1
            for it in files:
                fn = os.path.join(root, it).replace('\\','/')
                dn = os.path.join(real, fn[len(src):]) # target pathname
                p.makedirs(os.path.dirname(dn))
                print(dn)
                total_bytes += p.encryptFile(fn, dn, force)
                n += 1
        T1 = time.time()
        print('encrypting %s bytes in %d files and %d directories took %d seconds' % (_fmt_size(total_bytes), n, nn, T1-T0))

    def decryptFile(p, virtualpath, dest, force=False):
        "Decrypt a file from a virtual pathname and puts it in 'dest' (a real pathname or file-like object)"
        f = open(p.getFilePath(virtualpath), 'rb')
        
        # Get encrypted header
        h = f.read(68)
        hnonce, hpayload, htag = h[:12], h[12:-16], h[-16:]

        # Get content key
        dh = AES.new(p.pk, AES.MODE_GCM, nonce=hnonce).decrypt_and_verify(hpayload, htag)
        assert dh[:8] == b'\xFF'*8
        key = dh[8:] # 256-bit AES key
        
        # Process contents (AES-GCM encrypted, too)
        if hasattr(dest, 'write'): # if it's file
            out = dest
        else:
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
        st = p.stat(virtualpath)
        if not hasattr(dest, 'write'):
            # restore original last access and modification time
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

    def makedirs(p, virtualpath):
        "Creates a new directory or tree in the vault"
        if (virtualpath[0] != '/'):
            raise BaseException('the vault path to decrypt must be absolute!')
        p.getDirPath(virtualpath, 1) # with create=True, intermediate directories are created on the fly

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
        realpath = p.getDirPath(virtualpath)
        dirId = p.getDirId(virtualpath)
        root = virtualpath
        dirs = []
        files = []
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

def aes_wrap(kek, C):
    "AES key wrapping according to RFC3394"
    if len(C)%8:
        raise BaseException("full 64 bits blocks required")
    n = len(C)//8
    A = bytearray(b'\xA6'*8)
    R = bytearray(A+C)
    for j in range(6):
        for i in range(1, n+1):
            B = AES.new(kek, AES.MODE_ECB).encrypt(A + R[i*8:i*8+8])
            t = bytearray(struct.pack('>Q', n*j+i))
            A = bytearray(map(operator.xor, B[:8], t))
            R[i*8:i*8+8] = B[8:]
    return A + R[8:]

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

# If a directory id file dir.c9r gets lost or corrupted, and there is no dirid.c9r
# backup in the associated contents directory, names in that directory can't be restored!
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

def init_vault(vault_dir, password=None):
    "Init a new V8 Vault in a pre-existant directory"
    if not os.path.exists(vault_dir):
        raise BaseException("Specified directory doesn't exist!")
    if os.listdir(vault_dir):
        raise BaseException("The directory is not empty!")

    print('Creating new vault in "%s"' % vault_dir)

    if not password:
        password = ask_new_password()

    # init the vault.cryptomator
    pk = get_random_bytes(32) # new 256-bit Primary master key
    hk = get_random_bytes(32) # new 256-bit HMAC master key
    # vault.cryptomator model with default values
    head = {'kid': 'masterkeyfile:masterkey.cryptomator', 'alg': 'HS256', 'typ': 'JWT'}
    payl = {'jti': None, 'format': 8, 'cipherCombo': 'SIV_GCM', 'shorteningThreshold': 220}
    payl['jti'] = str(uuid.uuid4()) # random UUID string identifying this vault
    # jsonify & base64 encode vault.cryptomator structures
    s = base64.b64encode(json.dumps(head).encode()) + b'.' + base64.b64encode(json.dumps(payl).encode())
    # get their combined HMAC-SHA-256 with both keys
    h = HMAC.new(pk+hk, s, digestmod=SHA256)
    # write vault.cryptomator
    open(os.path.join(vault_dir, 'vault.cryptomator'), 'wb').write(s + b'.' + base64.urlsafe_b64encode(h.digest()))

    # masterkey.cryptomator model with default scrypt values
    master = {'version': 999, 'scryptSalt': None, 'scryptCostParam': 32768, 'scryptBlockSize': 8,
    'primaryMasterKey': None, 'hmacMasterKey': None, 'versionMac': None}
    scryptSalt = get_random_bytes(8) # random 64-bit salt
    master['scryptSalt'] = base64.b64encode(scryptSalt).decode()
    # get the encryption key from password
    kek = hashlib.scrypt(password.encode('utf-8'),
                               salt=scryptSalt,
                               n=master['scryptCostParam'], r=master['scryptBlockSize'], p=1,
                               maxmem=0x7fffffff, dklen=32)
    # wrap and encodes the master keys
    master['primaryMasterKey'] = base64.b64encode(aes_wrap(kek, pk)).decode()
    master['hmacMasterKey'] = base64.b64encode(aes_wrap(kek, hk)).decode()
    # get the HMAC-SHA-256 of the version number (as 32-bit Big Endian) using the HMAC key only
    h = HMAC.new(hk, int(master['version']).to_bytes(4, 'big'), digestmod=SHA256)
    master['versionMac'] = base64.b64encode(h.digest()).decode()
    # finally, write the new masterkey.cryptomator
    open(os.path.join(vault_dir, 'masterkey.cryptomator'), 'w').write(json.dumps(master))

    # init the encrypted root directory
    os.mkdir(os.path.join(vault_dir, 'd')) # default base directory
    aes = AES.new(hk+pk, AES.MODE_SIV)
    e, tag = aes.encrypt_and_digest(b'') # unencrypted root directory ID is always empty
    # encrypted root directory ID SHA-1, Base32 encoded
    edid = base64.b32encode(hashlib.sha1(tag+e).digest()).decode()
    # create the encrypted root directory (in vault_dir/d/<2-SHA1-chars>/<30-SHA1-chars>)
    os.mkdir(os.path.join(vault_dir, 'd', edid[:2]))
    os.mkdir(os.path.join(vault_dir, 'd', edid[:2], edid[2:]))

    # create a backup dirid.c9r (=empty encrypted file). See details in encryptFile.
    hnonce = get_random_bytes(12)
    payload = bytearray(b'\xFF'*8 + get_random_bytes(32))
    epayload, tag = AES.new(pk, AES.MODE_GCM, nonce=hnonce).encrypt_and_digest(payload)
    open(os.path.join(vault_dir, 'd', edid[:2], edid[2:], 'dirid.c9r'), 'wb').write(hnonce+payload+tag)
    print('done.')
    print ("It is strongly advised to open the new vault with --print-keys\nand annotate the master keys in a safe place!")
    
def ask_new_password():
    "Ask for a new password and check it"
    password = None
    if not password:
        check = 0
        if check != 0: print('The passwords you typed do not match!')
        while check != password:
            password = getpass.getpass('Please type the new password: ')
            check = getpass.getpass('Confirm the password: ')
    return password


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

    parser = argparse.ArgumentParser(description="Access to a Cryptomator V8 vault")
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
            we = Wordsencoder(os.path.join(os.path.dirname(sys.argv[0]), '4096words_en.txt'))
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
        print('An operation must be specified among alias, backup, decrypt, encrypt, ls, makedirs')
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
    elif extras[0] == 'decrypt': # decrypt files or directories
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
    elif extras[0] == 'makedirs':
        if len(extras) != 2:
            print('please use: makedirs <virtual_pathname>') # intermediate directories get created
            sys.exit(1)
        v.makedirs(extras[1])
    elif extras[0] == 'encrypt': # encrypt files or directories
        if len(extras) != 3:
            print('please use: encrypt <real_pathname_destination> <virtual_pathname_destination>')
            sys.exit(1)
        if os.path.isdir(extras[1]):
            v.encryptDir(extras[1], extras[2])
        else:
            v.encryptFile(extras[1], extras[2])
            print('done.')
    else:
        print('Unknown operation:', extras[0])
        sys.exit(1)
