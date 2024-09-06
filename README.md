# pycryptomator

A simple Python3 script to access a Cryptomator V8 vault and carry on some useful operations like:

```
ls       list virtual file system files and directories in decrypted form, with true size and times
decrypt  decrypt a file or directory from the vault's virtual filesystem into a given destination
alias    show the real pathname linked to a virtual one
backup   backup the Directory IDs (required to decrypt names) in a ZIP file
```

Passing a couple options, you can show you master keys or recover them in case configuration files are corrupted:

`--print-keys [a85 | b64]` shows the decrypted primary and hmac master key in ASCII85 or BASE64 form, to annotate them in a safe place for recovering purposes

`--master-keys`  grants access to the vault even in case of lost configuration files `vault.cryptomator` and/or `masterkey.cryptomator`, provided the master keys in ASCII85 or BASE64 form
