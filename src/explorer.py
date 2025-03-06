#!/usr/bin/env python3

# explorer.py | v0.1.3 | 30/10/2019 | by alimahouk
# ---------------------------------------------
# ABOUT THIS FILE
# ---------------------------------------------
# This is the Block Explorer program that can print
# all the details of an identity block to the console
# for human viewing.
#
# USAGE
# You can pass in either the identifier of the block
# (in plain text form, not the hash, e.g. foobar; this
# option requires having a Nomicle installation) or the
# path to a block file.

import argparse
import hashlib
import os
from distutils.util import strtobool
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from PyNomicle.nomicle import IdentityBlock


#
# CONSTANTS
#
CONF_KEY_BLOCK_PATH = "blockpath"
CONF_KEY_ID_BLOB = "blob"               # This is a flag used to tell the program whether to treat the identity file in binary mode rather than text.
CONF_KEY_ID_PATH = "idpath"
CONF_KEY_KEY_PATH = "keypath"
CONF_SYMBOL_COMMENT = "#"
FILE_EXT_NCLE = "ncle"

if os.name == "nt":
        PATH_NCLE_DIR_DATA = Path(os.environ["APPDATA"]) / "NCLE"
        PATH_NCLE_DIR_COMMON = Path(os.environ["APPDATA"]) / "NCLE"
        PATH_NCLE_DIR_CONF = Path(os.environ["APPDATA"]) / "NCLE"

        PATH_NCLE_DIR_BLOCKS = PATH_NCLE_DIR_DATA / "blocks"
        PATH_NCLE_FILE_CONF = PATH_NCLE_DIR_CONF / "ncle.conf"
        PATH_NCLE_FILE_ID = PATH_NCLE_DIR_COMMON / "id"
        PATH_NCLE_FILE_KEY = PATH_NCLE_DIR_CONF / "privkey.pem"
else:
        PATH_NCLE_DIR_DATA = Path("/usr/local/var/ncle")
        PATH_NCLE_DIR_COMMON = Path("/usr/local/share/ncle")
        PATH_NCLE_DIR_CONF = Path("/usr/local/etc/ncle")
        
        PATH_NCLE_DIR_BLOCKS = PATH_NCLE_DIR_DATA / "blocks"
        PATH_NCLE_FILE_CONF = PATH_NCLE_DIR_CONF / "ncle.conf"
        PATH_NCLE_FILE_ID = PATH_NCLE_DIR_COMMON / "id"
        PATH_NCLE_FILE_KEY = PATH_NCLE_DIR_CONF / "privkey.pem"
##########

class Explorer:   
        def __init__(self):
                self.blockPath = PATH_NCLE_DIR_BLOCKS
                self.idPath = PATH_NCLE_FILE_ID
                self.isBlobMode = False                 # This means the program reads the identity file in binary mode (i.e. the file could contain anything).
                self.privateKeyPath = PATH_NCLE_FILE_KEY

                self.readConfig()

                self.privateKey = self.loadPrivateKey()
                self.userRawIdentifier = self.readIdentity()
                if self.userRawIdentifier is not None and len(self.userRawIdentifier) > 0:
                        self.userIdentifier = hashlib.sha256(self.userRawIdentifier.encode()).digest()
                else:
                        self.userIdentifier = None

        def loadPrivateKey(self):
                if  os.path.exists(self.privateKeyPath):
                        keyFile = open(self.privateKeyPath, "rb")
                        loadedPrivateKey = serialization.load_pem_private_key(
                                keyFile.read(),
                                password=None,
                                backend=default_backend()
                        )
                        return loadedPrivateKey
                else:
                        return None

        def print(self, block):
                if block is not None:
                        # Create a new block to use the baseline target for calculating difficulty.
                        baselineTarget = IdentityBlock().unpackTarget()
                        target = block.unpackTarget()
                        
                        serialisedPublicKey = block.publicKey.public_bytes(
                                        encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )

                        print(f"VERSION: {block.version}")
                        print(f"TOKEN: {block.identifier.hex()}")
                        print(f"HASH: {block.blockHash.hex()}")
                        print(f"TARGET: {target[2]:#0{66}x}, (EXPONENT: {target[0]}, MANTISSA: {target[1]})")
                        print(f"DIFFICULTY: {baselineTarget[2] / float(target[2])}")
                        print(f"TIMESTAMP CREATED: {block.timestampCreated}")
                        print(f"TIMESTAMP UPDATED: {block.timestampUpdated}")
                        print(serialisedPublicKey.decode("ascii"))

                        if self.userIdentifier is not None and \
                           block.identifier == self.userIdentifier and \
                           self.privateKey is not None and \
                           block.publicKey.public_numbers() == self.privateKey.public_key().public_numbers():
                                print("YOU CURRENTLY OWN THIS IDENTITY BLOCK")

        def readConfig(self):
                try:
                        with open(PATH_NCLE_FILE_CONF, "r") as file:
                                configLines = file.read().strip().split("\n")
                                for line in configLines:
                                        if not line.startswith(CONF_SYMBOL_COMMENT):
                                                config = line.split(" ", 1)
                                                key = config[0].strip()
                                                if key == CONF_KEY_BLOCK_PATH:
                                                        self.blockPath = Path(config[1].strip())
                                                elif key == CONF_KEY_ID_BLOB:
                                                        self.isBlobMode = bool(strtobool(config[1].strip()))
                                                elif key == CONF_KEY_ID_PATH:
                                                        self.idPath = Path(config[1].strip())
                                                elif key == CONF_KEY_KEY_PATH:
                                                        self.privateKeyPath = Path(config[1].strip())
                except Exception:
                        # No config file found.
                        pass
        
        def readIdentity(self):
                if self.isBlobMode:
                        with open(self.idPath, "rb") as file:
                                identifier = file.read()
                else:
                        with open(self.idPath, "r") as file:
                                identifier = file.read().strip().lower()  # Nomicle is case-insensitive when it comes to identifiers.
                return identifier


if __name__ == "__main__":
        parser = argparse.ArgumentParser(description="Print the details of a Nomicle identity block.")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-p", "--path", type=str, help="The full file path to a block.")
        group.add_argument("-i", "--identifier", type=str, help="A Nomicle identifier.")
        args = parser.parse_args()

        explorer = Explorer()

        if args.path is not None:
                block = IdentityBlock.read(args.path)
        elif args.identifier is not None:
                token = hashlib.sha256(args.identifier.encode()).hexdigest()
                block = IdentityBlock.read(Path(explorer.blockPath) / (token + "." + FILE_EXT_NCLE))
                if block is None:
                        print(f"No block exists for identifier '{args.identifier}'")
        
        explorer.print(block)
