# Block Explorer

[← Back to Main Documentation](index.md)

Block Explorer is a program that can print all the details of an identity block to the console for human viewing. It is available for download from the [Nomicle Downloads](download.md#individual-components) page.

## Prerequisites

The program is a single Python script. It requires:

- [Python 3](https://www.python.org/download/releases/3.0/)
- The [cryptography](https://cryptography.io/en/latest/) Python package
- The [PyNomicle](download.md#libraries) library

## Usage

You can pass in either:

- The identifier of the block (in plain text form, not the hash, e.g. foobar; this option requires having a Nomicle installation)
- The path to a nomicle file

### Example 1: Using an Identifier

Starting the program with a specific identifier; use the "-i" or "--identifier" flag:

```bash
$ python3 explorer.py -i ali

VERSION: 0
TOKEN: 94419b99b12c11133a4dfeccc3e17885974beb48f7827c48239aabfbcad238d8
HASH: 00009ec8f68786b5
TARGET: 0x0000ffff00000000000000000000000000000000000000000000000000000000, (EXPONENT: 31, MANTISSA: 65535)
DIFFICULTY: 1.0
TIMESTAMP CREATED: 2020-06-10 21:52:48
TIMESTAMP UPDATED: 2020-06-10 21:52:50
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAES+WcJVfPsSFpJmva7MfVlkThJV1sljt9
BYaVJuzm84ztDRAojyEZ8pUGsfcEEgrs0XcC+l/4ls3nh9kylnqXeg==
-----END PUBLIC KEY-----

YOU CURRENTLY OWN THIS IDENTITY BLOCK
```

The last line is only printed if your public key (which is derived from your Nomicle private key) matches the one in the nomicle.

### Example 2: Using a File Path

Starting the program with the path to a nomicle file; use the "-p" or "--path" flag:

```bash
$ python3 explorer.py -p /usr/local/var/ncle/blocks/94419b99b12c11133a4dfeccc3e17885974beb48f7827c48239aabfbcad238d8.ncle

VERSION: 0
TOKEN: 94419b99b12c11133a4dfeccc3e17885974beb48f7827c48239aabfbcad238d8
HASH: 00009ec8f68786b5
TARGET: 0x0000ffff00000000000000000000000000000000000000000000000000000000, (EXPONENT: 31, MANTISSA: 65535)
DIFFICULTY: 1.0
TIMESTAMP CREATED: 2020-06-10 21:52:48
TIMESTAMP UPDATED: 2020-06-10 21:52:50
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAES+WcJVfPsSFpJmva7MfVlkThJV1sljt9
BYaVJuzm84ztDRAojyEZ8pUGsfcEEgrs0XcC+l/4ls3nh9kylnqXeg==
-----END PUBLIC KEY-----
```

## More Information

More information on what each field means is available in the [developer documentation](developer/fileformat.md).
