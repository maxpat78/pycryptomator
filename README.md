# pycryptomator
 utilty to access a Cryptomator V8 vault from command line with Python 3

A simple Python3 script to access a Cryptomator vault and carry on some useful operations like:

`alias`    show the real pathname linked to a virtual one
`ls`       list virtual file system files and directories in decrypted form, with true size and times
`backup`   backup the Directory IDs (required to decrypt names) in a ZIP file
`decrypt`  decrypt a file from the vault's virtual filesystem into a destination file

`--print-keys [a85 | b64]`
to show the decrypted 2 master keys in ASCII85 or BASE64 form and annotate them in a safe place, for recovering purposes

`--master-keys`
to access the vault even in case of lost configuration files `vault.cryptomator` and/or `masterkey.cryptomator`, providing the 2 master keys in ASCII85 or BASE64 form
