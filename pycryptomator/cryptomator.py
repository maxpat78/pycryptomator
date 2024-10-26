"""

   MIT License

   Copyright (c) 2024 maxpat78

"""
import getpass, hashlib, struct, base64
import json, sys, io, os, operator, re
import time, zipfile, locale, uuid, shutil, fnmatch
from os.path import *
from itertools import groupby
from operator import itemgetter

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import HMAC, SHA256
    from Cryptodome.Random import get_random_bytes
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256
    from Crypto.Random import get_random_bytes


class PathInfo():
    def __init__ (p):
        p.pathname = ''     # virtual (vault's) pathname to query info for
        p.longName = ''     # store the encrypted long name, if any
        p.dirId = ''        # directory id to crypt names inside the directory (or this file name, if it is a file)
        p.realPathName = '' # real (filesystem's) pathname derived crypting the virtual .pathname
                            # when making dirs: also, intermediate dir to create
        p.realDir = ''      # real (filesystem's) contents directory associated to directory .pathname or containing file .pathname
        p.hasSym = ''       # path to the symlink.c9r, if it is a symbolic link
        p.isDir = 0         # whether it is (or points to) a directory
        p.pointsTo = ''     # destination of the symbolic link, if any
        p.exists = 0        # if it exists on disk
    
    def __str__(p):
        base = '<%s' % (('nonexistent ','')[p.exists])
        if p.hasSym:
            base += 'PathInfo.Symlink (%s) "%s" -> "%s"' % (("File","Directory")[p.isDir], p.pathname, p.pointsTo)
        elif p.isDir:
            base += 'PathInfo.Directory "%s" (%s)' % (p.pathname, p.realDir)
        else:
            base += 'PathInfo.File "%s"' % (p.pathname)
        return base + " .realPathName=%s>" % (p.realPathName)

    @property
    def nameC9(p):
        if not p.longName: return p.realPathName
        return join(p.realPathName, 'name.c9s')

    @property
    def contentsC9(p):
        if not p.longName or p.isDir: return p.realPathName
        return join(p.realPathName, 'contents.c9r')

    @property
    def dirC9(p):
        if not p.isDir: return ''
        return join(p.realPathName, 'dir.c9r')


class Vault:
    "Handles a Cryptomator vault"
    def __init__ (p, directory, password=None, pk=None, hk=None):
        if not exists(directory):
            raise BaseException('Vault directory does not exist!')
        if not isdir(directory):
            raise BaseException('Not a directory: '+directory)
        p.base = directory # store vault base directory
        vcs = 'vault.cryptomator'
        config = join(p.base, vcs)
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
        p.master_path = join(p.base, kid[14:]) # masterkey.cryptomator path
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
        p.root = join(p.base, 'd', edid[:2], edid[2:]) # store encrypted root directory
        if not exists(p.root):
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
        if type(dirId) == type(b''): dirId = dirId.decode()
        aes = AES.new(p.hk+p.pk, AES.MODE_SIV)
        es, tag = aes.encrypt_and_digest(dirId.encode())
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

    def getInfo(p, virtualpath):
        "Query information about a vault's virtual path name and get a PathInfo object"
        dirId = '' # root id is null
        info = PathInfo()
        info.pathname = virtualpath
        info.realDir = p.root
        if virtualpath == '/':
            info.isDir = 1
            info.exists = 1
            return info
        parts = virtualpath.split('/')
        i, j = -1, len(parts)-1
        
        while i < j:
            i += 1
            if not parts[i]: continue
            # build the real dir path and the encrypted name
            hdid = p.hashDirId(dirId)
            ename = p.encryptName(dirId.encode(), parts[i].encode())
            rp = join(p.base, 'd', hdid[:2], hdid[2:]) # real base directory
            info.realDir = rp
            isLong = 0
            if len(ename) > p.shorteningThreshold:
                isLong = 1
                # SHA-1 hash, Base64 encoded, of the encrypted long name
                shortn = base64.urlsafe_b64encode(hashlib.sha1(ename).digest()).decode() + '.c9s'
                c9s = join(rp, shortn, 'name.c9s') # contains a 'name.c9s' for both files and directories
                diridfn = join(rp, shortn, 'dir.c9r')
            else:
                diridfn = join(rp, ename.decode(), 'dir.c9r')

            dirId = p.dirid_cache.get(diridfn, '') # try to retrieve dirId from cache
            if not dirId and exists(diridfn):
                dirId = open(diridfn).read()
                p.dirid_cache[diridfn] = dirId # cache directory id
            info.dirId = dirId
            info.realPathName = dirname(diridfn)
            if i == j:
                info.realPathName = dirname(diridfn)
                info.exists = exists(info.realPathName)
                if exists(diridfn):
                    info.isDir = 1
                    hdid = p.hashDirId(dirId)
                    rp = join(p.base, 'd', hdid[:2], hdid[2:])
                    info.realDir = rp
                    info.exists = 1
                info.dirId = dirId
                if isLong:
                    info.longName = ename
                sl = join(dirname(diridfn), 'symlink.c9r')
                if exists(sl):
                    info.hasSym = sl
                    resolved = p.resolveSymlink(virtualpath, sl)
                    info.pointsTo = resolved[0]
                    try:
                        iinfo = p.getInfo(resolved[0])
                        info.dirId = iinfo.dirId
                        info.isDir = iinfo.isDir
                        info.realDir = iinfo.realDir
                        #~ info.exists = iinfo.exists # .exists refers to link file, not target
                    except:
                        pass
            if not exists(info.realPathName):
                info.pathname = join('/', *parts[:i+1]) # store the first non-existant part
                return info
        return info

    def resolveSymlink(p, virtualpath, symlink):
        src = open(symlink, 'rb')
        sl = io.BytesIO()
        Vault._decryptf(p.pk, src, sl)
        sl.seek(0)
        symlink = target = sl.read().decode()
        if target[0] != '/':
            # recreate and normalize the path relative to virtualpath
            target = normpath(join(dirname(virtualpath), target)).replace('\\','/')
        return (target, symlink)

    def _encryptf(K, src, dst):
        "Raw encrypt with AES key 'K', from 'src' stream to 'dst' stream"
        hnonce = get_random_bytes(12) # random 96-bit header nonce
        key = get_random_bytes(32) # random 256-bit content encryption key
        payload = bytearray(b'\xFF'*8 + key)
        epayload, tag = AES.new(K, AES.MODE_GCM, nonce=hnonce).encrypt_and_digest(payload)
        # write 68 byte header: nonce, encrypted key and tag
        dst.write(hnonce)
        dst.write(epayload)
        dst.write(tag)
        # encrypt single blocks
        n = 0
        while True:
            s = src.read(32768) # a plaintext block is at most 32K
            if not s: break
            nonce = get_random_bytes(12) # random 96-bit nonce
            aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
            aes.update(struct.pack('>Q', n)) # AAD: 64-bit block number
            aes.update(hnonce) # AAD: header nonce
            es, tag = aes.encrypt_and_digest(s)
            # write block nonce, payload and tag
            dst.write(nonce)
            dst.write(es)
            dst.write(tag)
            n += 1

    def encryptFile(p, src, virtualpath, force=False, move=False):
        "Encrypt a 'src' file into a pre-existant vault's virtual directory (or a file-like object into a real path)"
        if hasattr(src, 'read'): # if it's file
            f = src
        else:
            if not exists(src):
                raise BaseException('Source file does not exist: '+src)
            f = open(src, 'rb')
        if not basename(virtualpath).endswith('dirid.c9r'):
            rp = p.create(virtualpath)
        else:
            rp = virtualpath
        out = open(rp,'wb')
        Vault._encryptf(p.pk, f, out)
        cb = out.tell()
        out.close()
        f.close()
        if not hasattr(src, 'read'):
            st = os.stat(src)
            os.utime(out.name, (st.st_atime, st.st_mtime))
            if move:
                os.remove(src)
        return cb

    def encryptDir(p, src, virtualpath, force=False, move=False):
        if (virtualpath[0] != '/'):
            raise BaseException('the vault path must be absolute!')
        src_dir = basename(src) # directory name we want to encrypt
        real = p.mkdir(virtualpath)
        n=0 # files count
        nn=0 # dirs count
        total_bytes = 0
        T0 = time.time()
        for root, dirs, files in os.walk(src):
            nn+=1
            for it in files+dirs:
                fn = join(root, it)
                dn = join(virtualpath, src_dir, fn[len(src)+1:]) # target pathname
                p.mkdir(dirname(dn))
                if it in files:
                    total_bytes += p.encryptFile(fn, dn, force, move)
                    n += 1
                else:
                    p.mkdir(dn) # makes empty directories, also
                print(dn)
        if move:
            print('moved', src)
            shutil.rmtree(src)
        T1 = time.time()
        print('encrypting %s bytes in %d files and %d directories took %d seconds' % (_fmt_size(total_bytes), n, nn, T1-T0))

    def _decryptf(K, src, dst):
        "Raw decrypt with AES key 'K', from 'src' stream to 'dst' stream"
        # Get encrypted header
        h = src.read(68)
        hnonce, hpayload, htag = h[:12], h[12:-16], h[-16:]

        # Get content key
        dh = AES.new(K, AES.MODE_GCM, nonce=hnonce).decrypt_and_verify(hpayload, htag)
        assert dh[:8] == b'\xFF'*8
        key = dh[8:] # 256-bit AES key
        
        # Process contents (AES-GCM encrypted, too)
        n = 0
        while True:
            s = src.read(32768+28) # an encrypted block is at most 32K + 28 bytes
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
            dst.write(ds)
            n += 1

    def decryptFile(p, virtualpath, dest, force=False, move=False):
        "Decrypt a file from a virtual pathname and puts it in 'dest' (a real pathname or file-like object)"
        info = p.getInfo(virtualpath)
        while info.pointsTo:
            info = p.getInfo(info.pointsTo)
        rp = info.realPathName
        f = open(rp, 'rb')
        if hasattr(dest, 'write'): # if it's file
            out = dest
        else:
            if (dest == '-'):
                out = sys.stdout.buffer
            else:
                if exists(dest) and not force:
                    raise BaseException('destination file "%s" exists and won\'t get overwritten!'%dest)
                out = open(dest, 'wb')

        Vault._decryptf(p.pk, f, out)
        
        f.close()
        if dest != '-': out.close()
        st = p.stat(virtualpath)
        if dest != '-' and not hasattr(dest, 'write'):
            # restore original last access and modification time
            os.utime(dest, (st.st_atime, st.st_mtime))
            if move:
                p.remove(info.pathname)
        return st.st_size
    
    def decryptDir(p, virtualpath, dest, force=False, move=False):
        if (virtualpath[0] != '/'):
            raise BaseException('the vault path to decrypt must be absolute!')
        x = p.getInfo(virtualpath)
        if not x.exists:
            raise BaseException(virtualpath + ' does not exist!')
        n=0
        nn=0
        total_bytes = 0
        T0 = time.time()
        for root, dirs, files in p.walk(virtualpath):
            nn+=1
            for it in files+dirs:
                fn = join(root, it)
                dn = join(dest, fn[1:]) # target pathname
                bn = dirname(dn) # target base dir
                if not exists(bn):
                    os.makedirs(bn)
                if it in files:
                    total_bytes += p.decryptFile(fn, dn, force, move)
                    n += 1
                else:
                    if not exists(dn): os.makedirs(dn)
                print(dn)
        if move:
            print('moved', virtualpath)
            p.rmtree(virtualpath)
        T1 = time.time()
        print('decrypting %s bytes in %d files and %d directories took %d seconds' % (_fmt_size(total_bytes), n, nn, T1-T0))

    def stat(p, virtualpath):
        "Perform os.stat on a virtual pathname"
        x = p.getInfo(virtualpath)
        return os.stat(x.contentsC9)

    def mkdir(p, virtualpath):
        "Create a new directory or tree in the vault"
        if (virtualpath[0] != '/'):
            raise BaseException('the vault path to the directory to create must be absolute!')
        while 1:
            x = p.getInfo(virtualpath)
            if x.exists: break
            # make the encrypted directory
            os.mkdir(x.realPathName)
            # assign a random directory id
            dirId = str(uuid.uuid4()).encode()
            open(join(x.realPathName,'dir.c9r'),'wb').write(dirId)
            # make the associated contents directory and store a backup copy of the dir id
            hdid = p.hashDirId(dirId)
            rp = join(p.base, 'd', hdid[:2], hdid[2:])
            os.makedirs(rp)
            backup = join(rp, 'dirid.c9r')
            p.encryptFile(io.BytesIO(dirId), backup)
            if x.longName: open(x.nameC9,'wb').write(x.longName)
        return x.realDir

    def create(p, virtualpath):
        "Create an empty file and, eventually, its intermediate directories"
        p.mkdir(dirname(virtualpath)) # ensure base path exists
        x = p.getInfo(virtualpath)
        if x.longName:
            dn = dirname(x.nameC9)
            if not exists(dn): os.makedirs(dn)
            open(x.nameC9,'wb').write(x.longName)
        open(x.contentsC9,'w').close()
        return x.contentsC9

    def remove(p, virtualpath):
        "Delete a file or symlink"
        x = p.getInfo(virtualpath)
        if not x.exists:
            print('rm: %s: no such file' % virtualpath)
            return
        if x.isDir and not x.hasSym:
            print('rm: %s: is a directory' % virtualpath)
            return
        if x.hasSym:
            # remove symlink.c9r (and dir.c9r if link to a directory) and its parent
            if x.isDir: os.remove(x.dirC9)
            os.remove(x.hasSym)
            os.rmdir(x.realPathName)
        if x.longName:
            # remove name.c9s, contents.c9r and their .c9s parent
            os.remove(x.nameC9)
            os.remove(x.contentsC9)
            os.rmdir(x.realPathName)
        else:
            # remove the .c9r file
            if not x.hasSym: os.remove(x.realPathName)

    def rmdir(p, virtualpath):
        "Delete an empty directory"
        x = p.getInfo(virtualpath)
        if not x.exists:
            print('rmdir: %s: no such directory' % virtualpath)
            return
        if not x.isDir:
            print('rmdir: %s: is not a directory' % virtualpath)
            return
        files = os.listdir(x.realDir)
        if 'dirid.c9r' in files:
            files.remove('dirid.c9r')
        if len(files):
            print('rmdir: %s: directory is not empty' % virtualpath)
            return
        c9r = join(x.realDir,'dirid.c9r') # dirid backup
        if exists(c9r): os.remove(c9r)
        os.rmdir(x.realDir) # 30-chars part
        try:
            os.rmdir(dirname(x.realDir)) # 2-chars part
        except OSError:
            print("Could not remove %s while rmdir'ing %s" %(dirname(x.realDir), virtualpath))
            print("os.listdir returned", os.listdir(dirname(x.realDir)))
            # RemoveDirectory "marks a directory for deletion *on close*"
            print("NOTE: on Windows this could be due to caching problems, and NOT affects operation success!")
        if x.longName:
            # remove name.c9s, dir.c9r and their .c9s parent
            os.remove(x.nameC9)
            os.remove(x.dirC9)
            os.rmdir(x.realPathName)
        else:
            os.remove(x.dirC9)
            os.rmdir(x.realPathName)
        del p.dirid_cache[x.dirC9] # delete from cache also

    def rmtree(p, virtualpath):
        "Delete a full virtual directory tree"
        x = p.getInfo(virtualpath)
        if not x.exists:
            print('rmtree: %s: no such directory' % virtualpath)
            return
        if not x.isDir:
            print('rmtree: %s: is not a directory' % virtualpath)
            return
        # Delete all files, first
        ff, dd = 0, 1
        for root, dirs, files in p.walk(virtualpath):
            for it in files:
                fn = join(root, it)
                p.remove(fn)
                ff += 1
        # Then delete all directories, in bottom-up order
        for root, dirs, files in reversed(list(p.walk(virtualpath))):
            for it in dirs:
                dn = join(root, it)
                p.rmdir(dn)
                dd += 1
        # Finally, delete the empty base directory
        p.rmdir(virtualpath)
        print ('rmtree: deleted %d files in %d directories in %s' % (ff,dd,virtualpath))
            
    def ln(p, target, symlink):
        "Create a symbolic link"
        a = p.getInfo(symlink)
        if not exists(a.realPathName): os.mkdir(a.realPathName)
        out = open(join(a.realPathName, 'symlink.c9r'), 'wb')
        if os.name == 'nt' and target[0] == '/':
            target = calc_rel_path(target, symlink)
            print("warning: absolute target pathname won't work with Windows")
            print("relative conversion supplied:", target)
        Vault._encryptf(p.pk, io.BytesIO(target.encode()), out) # does not check target existance
        out.close()

    def ls(p, pathnames, opts):
        "List files and directories"
        #~ print('DEBUG: ls called with %d args'%len(pathnames))
        def _realsize(n):
            "Return the decrypted file size"
            if n == 68: return 0 # header only
            cb = (n - 68 + (32768+28-1)) // (32768+28) # number of encrypted blocks
            size = n - 68 - (cb*28)
            if size < 0: size = 0 #symlinks
            return size

        # [(root, name, is_file?, size, mtime, ext, symlink)]
        results = []

        # Phase 1: collect info about listed objects and build a table
        for pathname in pathnames:
            info = p.getInfo(pathname)
            if not info.exists:
                print(pathname, 'does not exist')
                continue
            if info.pointsTo:
                print(pathname, 'points to', info.pointsTo)
                pathname = info.pointsTo
            # bypass walking if it isn't a directory
            # works good with links?
            if not info.isDir:
                st = p.stat(pathname)
                size = _realsize(st.st_size)
                #~ info = p.getInfo(full)
                results += [(dirname(pathname) or '/', basename(pathname), True, size, st.st_mtime, splitext(pathname)[1].lower(), info.pointsTo)]
                continue
            for root, dirs, files in p.walk(pathname):
                for it in dirs:
                    full = join(root, it)
                    st = p.stat(full)
                    results += [(root, it, False, 0, st.st_mtime, '', '')]
                for it in files:
                    full = join(root, it)
                    st = p.stat(full)
                    size = _realsize(st.st_size)
                    info = p.getInfo(full)
                    results += [(root, it, True, size, st.st_mtime, splitext(it)[1].lower(), info.pointsTo)]
                if not opts.recursive: break
        #~ print('ls_new collected', results)
        # Phase 2: group by directory, and print (eventually sorted) results
        gtot_size, gtot_files, gtot_dirs = 0, 0, 0
        for group in groupby(results, lambda x: x[0]):
            if opts.banner: print('\n  Directory of', group[0], '\n')
            files = dirs = 0
            tot_size = 0
            G = list(group[1])
            if opts.sorting:
                # build a tuple suitable for itemgetter/key function
                sort = []
                sort_reverse = 0
                sort_dirfirst = 0
                for c in opts.sorting:
                    if c == '-':
                        sort_reverse = 1
                        continue
                    if c == '!':
                        sort_dirfirst = 1
                        continue
                    sort += [{'N':1,'S':3,'D':4,'E':5}[c]]
                if sort_dirfirst: sort.insert(0, 2)
                sort = tuple(sort)
                #~ print('DEBUG: sort tuple', sort)
                #~ print('DEBUG: unsorted list', G)
                if G: G = sorted(G, key=itemgetter(*sort), reverse=sort_reverse)
                #~ print('DEBUG: sorted list', G)
            if not opts.banner:
                for r in G:
                    print(r[1])
            else:
                for r in G:
                    if not r[2]:
                        dirs += 1
                        print('%12s  %s  %s' %('<DIR>', time.strftime('%Y-%m-%d %H:%M', time.localtime(r[4])), r[1]))
                    else:
                        files += 1
                        tot_size += size
                        if r[6]:
                            print('%12s  %s  %s [--> %s]' %('<SYM>', time.strftime('%Y-%m-%d %H:%M', time.localtime(r[4])), r[1], r[6]))
                        else:
                            print('%12s  %s  %s' %(_fmt_size(r[3]), time.strftime('%Y-%m-%d %H:%M', time.localtime(r[4])), r[1]))
                if opts.banner: print('\n%s bytes in %d files and %d directories.' % (_fmt_size(tot_size), files, dirs))
                gtot_size += tot_size
                gtot_files += files
                gtot_dirs += dirs
        if opts.recursive and opts.banner:
            print('\n   Total files listed:\n%s bytes in %s files and %s directories.' % (_fmt_size(gtot_size), _fmt_size(gtot_files), _fmt_size(gtot_dirs)))

    def mv(p, src, dst):
        "Move or rename files and directories"
        a = p.getInfo(src)
        b = p.getInfo(dst)
        if not a.exists:
            print("Can't move nonexistent object %s"%src)
            return
        if a.realPathName == b.realPathName:
            print("Can't move an object onto itself: %s"%src)
            return
        if b.exists:
            if not b.isDir:
                print("Can't move %s, target exists already"%dst)
                return
            c = p.getInfo(join(dst, basename(src)))
            if c.exists:
                if c.isDir and os.listdir(c.realDir):
                    print("Can't move, target directory \"%s\" not empty"%c.pathname)
                    return
                elif not c.isDir:
                    print("Can't move \"%s\", target exists already"%c.pathname)
                    return
            shutil.move(a.realPathName, c.realPathName)
            if a.longName:
                open(c.nameC9,'wb').write(c.longName) # update long name
            return
        if a.longName:
            # long name dir (file) -> file
            if not a.isDir:
                shutil.move(a.contentsC9, b.realPathName)
                os.remove(a.nameC9)
                os.rmdir(a.realPathName)
                return
            else:
                os.remove(a.nameC9) # remove long name
        os.rename(a.realPathName, b.realPathName) # change the encrypted name

    # os.walk by default does not follow dir links
    def walk(p, virtualpath):
        "Traverse the virtual file system like os.walk"
        yield from p._walker(virtualpath, mode='walk')

    def glob(p, pathname):
        "Expand wildcards in pathname returning a list"
        return [x for x in p._walker(pathname, mode='glob')]

    def iglob(p, pathname):
        "Expand wildcards in pathname returning a generator"
        yield from p._walker(pathname, mode='glob')

    def _walker(p, pathname, mode='walk'):
        base, pred = match(pathname)
        x = p.getInfo(base)
        if not pred:
            if not x.exists or not x.isDir:
                # pred becomes the exact name
                base, pred = dirname(pathname) or '/', [basename(pathname)]
                x = p.getInfo(base)
        #~ print('debug: pathname, base, pred',pathname, base, pred)
        #~ if mode == 'glob':
            #~ if not x.exists:
                #~ yield ''
                #~ return
            #~ if not x.isDir or base == pred:
                #~ yield pathname
                #~ return
        realpath = x.realDir
        dirId = x.dirId
        root = base
        dirs = []
        files = []
        r = []
        for it in os.scandir(realpath):
            if it.name == 'dirid.c9r': continue
            is_dir = it.is_dir()
            if it.name.endswith('.c9s'): # deflated long name
                # A c9s dir contains the original encrypted long name (name.c9s) and encrypted contents (contents.c9r)
                ename = open(join(realpath, it.name, 'name.c9s')).read()
                dname = p.decryptName(dirId.encode(), ename.encode()).decode()
                if exists(join(realpath, it.name, 'contents.c9r')): is_dir = False
            else:
                dname = p.decryptName(dirId.encode(), it.name.encode()).decode()
            sl = join(realpath, it.name, 'symlink.c9r')
            if is_dir and exists(sl):
                # Decrypt and look at symbolic link target
                resolved = p.resolveSymlink(join(root, dname), sl)
                is_dir = False
            if pred:
                #~ print('testing %s against %s' % (dname, pred[0]))
                if not match(dname, pred[0]):
                    #~ print('no match')
                    continue
                # intermediate predicate matches directories only
                if not is_dir and len(pred) > 1:
                    #~ print('is file')
                    continue
            if is_dir: dirs += [dname]
            else: files += [dname]
        if mode == 'walk':
            yield root, dirs, files
            for it in dirs:
                subdir = join(root, it)
                yield from p.walk(subdir)
        else:
            pred = pred[1:]
            if not pred:
                #~ print('predicate exhausted, building result')
                for it in dirs+files:
                    yield join(root, it)
                return
            for it in dirs:
                yield from p.iglob(join(root, it, *pred))


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

def join(*args): return os.path.join(*args).replace('\\','/')

# If a directory id file dir.c9r gets lost or corrupted, and there is no dirid.c9r
# backup in the associated contents directory, names in that directory can't be restored!
def backupDirIds(vault_base, zip_backup):
    "Archive in a ZIP file all the DirectoryIDs with their encrypted tree, for backup purposes"
    if not exists(vault_base) or \
    not isdir(vault_base) or \
    not exists(join(vault_base,'vault.cryptomator')):
        raise BaseException(vault_base+' is not a valid Cryptomator vault directory!')
    zip = zipfile.ZipFile(zip_backup, 'w', zipfile.ZIP_DEFLATED)
    n = len(vault_base)
    df = 'dir.c9r'
    for root, dirs, files in os.walk(vault_base):
        if df in files:
            it = join(root[n+1:], df) # ZIP item name (relative name)
            s =  join(vault_base, it) # source file to backup with the plain text directory UUID
            zip.write(s, it)
    zip.close()

def init_vault(vault_dir, password=None):
    "Init a new V8 Vault in a pre-existant directory"
    if not exists(vault_dir):
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
    open(join(vault_dir, 'vault.cryptomator'), 'wb').write(s + b'.' + base64.urlsafe_b64encode(h.digest()))

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
    open(join(vault_dir, 'masterkey.cryptomator'), 'w').write(json.dumps(master))

    # init the encrypted root directory
    os.mkdir(join(vault_dir, 'd')) # default base directory
    aes = AES.new(hk+pk, AES.MODE_SIV)
    e, tag = aes.encrypt_and_digest(b'') # unencrypted root directory ID is always empty
    # encrypted root directory ID SHA-1, Base32 encoded
    edid = base64.b32encode(hashlib.sha1(tag+e).digest()).decode()
    # create the encrypted root directory (in vault_dir/d/<2-SHA1-chars>/<30-SHA1-chars>)
    os.mkdir(join(vault_dir, 'd', edid[:2]))
    os.mkdir(join(vault_dir, 'd', edid[:2], edid[2:]))

    # create a backup dirid.c9r (=empty encrypted file). See details in encryptFile.
    hnonce = get_random_bytes(12)
    payload = bytearray(b'\xFF'*8 + get_random_bytes(32))
    epayload, tag = AES.new(pk, AES.MODE_GCM, nonce=hnonce).encrypt_and_digest(payload)
    open(join(vault_dir, 'd', edid[:2], edid[2:], 'dirid.c9r'), 'wb').write(hnonce+payload+tag)
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

def match(s, p=None):
    """Test wether a given string 's' matches a predicate 'p' or split the
    predicate in two parts, without and with wildcards: origin and predicates list"""
    if not s or s == '/': return ('/', [])
    aa = s.split('/')
    i = 0
    if not p:
        while i < len(aa):
            if '*' in aa[i] or '?' in aa[i]: break
            i+=1
        #~ print('couple', aa[:i], aa[i:])
        first = '/'.join(aa[:i])
        second = aa[i:]
        if not first: first = '/'
        return first, second
    bb = p.split('/')
    while 1:
        if i in (len(aa), len(bb)): break
        if not fnmatch.fnmatch(aa[i], bb[i]):
            #~ print ('fnmatch',aa,'against',bb,': does not match')
            return 0
        i+=1
    #~ print ('fnmatch',aa,'against',bb,': matches')
    return 1

def calc_rel_path(base, child):
    "returns the path of base relative to child"
    base_parts = re.split(r'[\\/]+', abspath(base))
    child_parts = re.split(r'[\\/]+', abspath(child))
    # strips common subpath, if any
    i=0
    while base_parts[i] == child_parts[i]: i += 1
    # returns base if they don't share anything
    if not i: return base
    n = len(child_parts) - 1 - i # counts path separators
    relpath = ''
    while n:
        relpath += '../'
        n -= 1
    relpath += '/'.join(base_parts[i:])
    return relpath
