# pycryptomator

A simple Python 3 script to access a Cryptomator V8 vault and carry on some useful operations like:

```
ls       list virtual file system files and directories in decrypted form, with true size and times
decrypt  decrypt a file or directory from the vault's virtual filesystem into a given destination
alias    show the real pathname linked to a virtual one
backup   backup the Directory IDs (required to decrypt names) in a ZIP file
```

Passing a couple options, you can show you master keys or recover them in case configuration files are corrupted:

`--print-keys [a85 | b64 | words]` shows the decrypted primary and hmac master key in ASCII85 or BASE64 form, or as a list of English words like Cryptomator itself, to annotate them in a safe place for recovering purposes.

`--master-keys`  grants access to the vault even in case of lost configuration files `vault.cryptomator` and/or `masterkey.cryptomator`, provided the master keys as ASCII85 or BASE64 strings; `- -` can be used to read the words list from standard input.

Functionality was tested in Windows 11 and Ubuntu 22.04 LTS Linux (under Windows WSL).

It's pure Python 3, with pycryptodome addon.

MIT licensed.
