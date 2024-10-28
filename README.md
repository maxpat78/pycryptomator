# pycryptomator

A Python 3 package to access a Cryptomator V8 vault and carry on some useful operations.

```
usage: pycryptomator  [-h] [--init] [--print-keys [{a85,b64,words}]] [--master-keys PRIMARY_KEY HMAC_KEY]
                      [--password PASSWORD] [--change-password]
                      vault_name

Access to a Cryptomator V8 vault

positional arguments:
  vault_name            Location of the existing Cryptomator V8 vault to open

options:
  -h, --help            show this help message and exit
  --init                Initialize a new vault in an empty directory
  --print-keys [{a85,b64,words}]
                        Print the raw master keys as a list of English words for Cryptomator (default), in ASCII85
                        (a85) or BASE64 (b64) format
  --master-keys PRIMARY_KEY HMAC_KEY
                        Primary and HMAC master keys in ASCII85 or BASE64 format, or - - to read a words list from
                        standard input
  --password PASSWORD   Password to unlock master keys stored in config file
  --change-password     Change the password required to open the vault
```

Passing a couple options, you can show you master keys or recover them in case
configuration files are corrupted:

`--print-keys` shows the decrypted primary and hmac master key in ASCII85
or BASE64 form, or as a list of English words like Cryptomator itself, to
annotate them in a safe place for recovering purposes.

`--master-keys`  grants access to the vault even in case of lost configuration
files `vault.cryptomator` and/or `masterkey.cryptomator`, provided the master
keys as ASCII85 or BASE64 strings; `- -` can be used to read the words list
from standard input.


After the `vault_name`, you can specify some useful operations like:

```
cd       change vault's current directory
ls       list unecrypted vault contents (with size and time)
mkdir    create a new directory/tree in the vault
mv       move or rename files and directories
ln       create a symbolic link
rm       erase files or directories
decrypt  decrypt a file or directory from the vault's virtual filesystem into a given destination
encrypt  encrypt a file or directory
alias    show the real pathname linked to a virtual one
backup   backup the Directory IDs (required to decrypt names) in a ZIP file
```

If no operation is specified, an interactive shell is launched on open vault. It can do transparent wildcards expansion (`*` and `?` only).

Functionality was tested in Windows 11 and Ubuntu 22.04 LTS Linux (under Windows WSL).

It's pure Python 3, with pycryptodome addon.

MIT licensed.
Absolutely no warranty!


# Internal commands

`*` and `?` wildcards can be specified on command line to enable automatic shell expansion.


`alias <pathname>`
show the real base64 (encrypted and obfuscated) pathname corresponding to the
vault's <pathname>

`backup <archive.zip>`
make in archive.zip a backup of all the directory id files dir.c9r
encountered in the vault tree: they are required to reconstruct original file
names

`cd <directory>`
make the specified vault's directory the current one in the pycryptomator
internal shell

```
decrypt [-m] [-f] <virtual_pathname_source1...> <real_pathname_destination>
decrypt <virtual_pathname_source> -
```
decrypt one or more files and/or directories to the specified destination in the
real file system. Option `-f` forces to overwrite existing files, `-m` moves 
(i.e. deletes) the source files after decryption. With `-` as destination, a
file is decrypted and printed to standard output.

`encrypt [-m] <real_pathname_source1...> <virtual_pathname_destination>`
encrypt one or more files and/or directories to the specified destination. If
the destination is a directory, it must exist. `-m` moves (i.e. deletes) the
source files after encryption.

`ln <target> <link>`
make a symbolic link <link> to a <target> file or directory in the vault.
It does not check for <target> existence.
An absolute <target> should be avoided, since it prevents portability
(i.e. to Windows).

`ls [-b] [-r] [-s NSDE-!] <virtual_path1> [...<virtual_pathN>]`
list files and directories with minimal informations like DOS DIR (type/size,
write time, name, symbolic link target).
`-b` prints bare names
`-r` traverses specified directories recursively
`-s` sorts results by one or more criteria: `N`ame, `S`ize, `D`ate, `E`xtension
(a.k.a. file type), `-` sorts in reverse order and `!` puts directories first.

`mkdir <dir1> [...<dirN>]`
make one or more directories or directory trees (i.e. intermediate directories
get created) in the vault.

`mv <source> [<source2>...<sourceN>] <destination>`
rename or move files and directories. If more files or directories are specified,
<destination> must be an existing directory and objects are moved inside it;
else, if <destination> does not exist, it renames the file or directory.

`rm [-f] <file1|dir1> [...<fileN|dirN>]`
remove files and directories. Root directory is protected against accidental
deletion. If a directory is not empty, `-f` switch is required to force its
removal.
