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
