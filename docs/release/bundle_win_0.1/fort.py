#!/usr/bin/env python3

# fort.py | v0.1 | 23/08/2019 | by alimahouk
# ---------------------------------------------
# ABOUT THIS FILE
# ---------------------------------------------
# This is the Foritifier program that is responsible for generating
# and fortifying identity blocks for the local user of the system.
#
# USAGE
# You can pass in the Nomicle identifier you would like to use to
# identify yourself using the -i or --identifier flag.

import argparse
import hashlib
import os
import sys
import time
from datetime import datetime, timedelta
from distutils.util import strtobool
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from PyNomicle.nomicle import IdentityBlock


#
# CONSTANTS
#
CONF_KEY_BLOCK_PATH = "blockpath"
CONF_KEY_ID_BLOB = "blob"               # This is a flag used to tell the program whether to treat the identity file in binary mode rather than text.
CONF_KEY_ID_PATH = "idpath"
CONF_KEY_INTENSITY = "intensity"
CONF_KEY_KEY_PATH = "keypath"
CONF_SYMBOL_COMMENT = "#"
FILE_EXT_NCLE = "ncle"
FORT_DEFAULT_INTENSITY = 5
MAX_NONCE = 2 ** 32                     # 4 billion

if os.name == "nt":
        PATH_NCLE_DIR_DATA = Path(os.environ["APPDATA"]) / "NCLE"
        PATH_NCLE_DIR_COMMON = Path(os.environ["APPDATA"]) / "NCLE"
        PATH_NCLE_DIR_CONF = Path(os.environ["APPDATA"]) / "NCLE"
else:
        PATH_NCLE_DIR_DATA = Path("/usr/local/var/ncle")
        PATH_NCLE_DIR_COMMON = Path("/usr/local/share/ncle")
        PATH_NCLE_DIR_CONF = Path("/usr/local/etc/ncle")
        
PATH_NCLE_DIR_BLOCKS = PATH_NCLE_DIR_DATA / "blocks"
PATH_NCLE_FILE_CONF = PATH_NCLE_DIR_CONF / "ncle.conf"
PATH_NCLE_FILE_ID = PATH_NCLE_DIR_COMMON / "id"
PATH_NCLE_FILE_KEY = PATH_NCLE_DIR_CONF / "privkey.pem"
PATH_FORT_FILE_CONF = PATH_NCLE_DIR_CONF / "fort.conf"
##########

class Fortifier():
        BOOST_DURATION = 30 # Seconds
        DEFAULT_CONFIG_NCLE = f"""{CONF_KEY_BLOCK_PATH} {PATH_NCLE_DIR_BLOCKS}
{CONF_KEY_KEY_PATH} {PATH_NCLE_FILE_KEY}
{CONF_KEY_ID_PATH} {PATH_NCLE_FILE_ID}
{CONF_KEY_ID_BLOB} 0 """
        DEFAULT_CONFIG_FORT = f"""{CONF_KEY_INTENSITY} {FORT_DEFAULT_INTENSITY}"""
        INTERVAL_BOOST = 30     # Minutes
        INTERVAL_IDLE = 3       # Seconds
        MAX_INTENSITY = 10

        def __init__(self):
                self.blockPath = PATH_NCLE_DIR_BLOCKS
                self.idPath = PATH_NCLE_FILE_ID
                self.isBlobMode = False                 # This means the program reads the identity file in binary mode (i.e. the file could contain anything).
                self.intensity = FORT_DEFAULT_INTENSITY
                self.privateKey = None
                self.privateKeyPath = PATH_NCLE_FILE_KEY
                self.userIdentifier = None
                self.userRawIdentifier = None

        def bootstrap(self):
                # Integrity checks.
                self.checkDirs()
                # Start with the config file to determine where some things ought to go.
                self.checkConfigFiles()
                self.readConfig()
                
                self.checkIdentityBlockPool()
                self.checkIdentityFile()
        
        def checkConfigFiles(self):
                if not os.path.exists(PATH_NCLE_FILE_CONF):
                        with open(PATH_NCLE_FILE_CONF, "w+") as newFile:
                                newFile.write(self.DEFAULT_CONFIG_NCLE)
                if not os.path.exists(PATH_FORT_FILE_CONF):
                        with open(PATH_FORT_FILE_CONF, "w+") as newFile:
                                newFile.write(self.DEFAULT_CONFIG_FORT)

        def checkDirs(self):
                if not os.path.exists(PATH_NCLE_DIR_CONF):
                        PATH_NCLE_DIR_CONF.mkdir(parents=True)
                if not os.path.exists(PATH_NCLE_DIR_COMMON):
                        PATH_NCLE_DIR_COMMON.mkdir(parents=True)
                if not os.path.exists(PATH_NCLE_DIR_DATA):
                        PATH_NCLE_DIR_DATA.mkdir(parents=True)
        
        def checkIdentityBlockPool(self):
                if not os.path.exists(self.blockPath):
                        path = Path(self.blockPath)
                        path.mkdir(parents=True)

        def checkIdentityFile(self):
                if not os.path.exists(self.idPath):
                        with open(self.idPath, "w+") as newFile:
                                newFile.write("")
        
        def dumpPrivateKey(self, privateKey):
                if privateKey is None:
                        raise ValueError("Fortifier.dumpPrivateKey(1): privateKey is None")
                # Dump the key file in PEM format.
                serialisedPrivateKey = privateKey.private_bytes(
                                        encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.PKCS8,
                                        encryption_algorithm=serialization.NoEncryption()
                                )
                newFile = open(self.privateKeyPath, "w+")
                newFile.write(serialisedPrivateKey.decode("ascii"))

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

        def pow(self, block):
                if block is None:
                        raise ValueError("Fortifier.pow(1): block is None")
                elif not isinstance(block, IdentityBlock):
                        raise TypeError("Fortifier.pow(1): block is not an instance of IdentityBlock")
                
                while 1:
                        # Sprints take place at regular intervals for several seconds.
                        currentTime = datetime.now()
                        scheduledBoost = currentTime + timedelta(minutes=self.INTERVAL_BOOST)
                        
                        block.timestampUpdated = currentTime
                        hash = int(block.hash().hex(), base=16)

                        target = block.unpackTarget()
                        print(f"TARGET: {target[2]:#0{66}x}")
                        print(f"TRYING {hash:#0{66}x}")
                        counter = 0
                        solved = False
                        startTime = time.time()
                        
                        for nonce in range(MAX_NONCE):
                                if hash < target[2]:
                                        solved = True
                                        break

                                currentTime = datetime.now()

                                if self.intensity < self.MAX_INTENSITY and \
                                   currentTime < scheduledBoost:
                                        time.sleep(self.intensity / self.MAX_INTENSITY)
                                # Running at max intensity means no delay whatsoever.

                                currentTime = datetime.now()
                                if currentTime >= scheduledBoost + timedelta(seconds=self.BOOST_DURATION):
                                        scheduledBoost = currentTime + timedelta(minutes=self.INTERVAL_BOOST)

                                
                                block.timestampUpdated = datetime.now()
                                block.nonce = nonce
                                counter += 1
                                hash = int(block.hash().hex(), base=16)
                                print(f"{counter:,}: {hash:#0{66}x}")
                        
                        if not solved:
                                for nonce in range(MAX_NONCE):
                                        if hash < target[2]:
                                                solved = True
                                                break

                                        currentTime = datetime.now()

                                        if self.intensity < self.MAX_INTENSITY and \
                                           currentTime < scheduledBoost:
                                                time.sleep(self.intensity / self.MAX_INTENSITY)

                                        currentTime = datetime.now()
                                        if currentTime >= scheduledBoost + timedelta(seconds=self.BOOST_DURATION):
                                                scheduledBoost = currentTime + timedelta(minutes=self.INTERVAL_BOOST)


                                        block.timestampUpdated = datetime.now()
                                        block.extraNonce = nonce
                                        counter += 1
                                        hash = int(block.hash().hex(), base=16)
                                        print(f"{counter:,}: {hash:#0{66}x}")
                        
                        if solved:
                                elapsed = int(time.time() - startTime)
                                print(f"FOUND PROOF-OF-WORK AT {datetime.now()}!")
                                print("IT TOOK {:02d}:{:02d}:{:02d}".format(elapsed // 3600, (elapsed % 3600 // 60), elapsed % 60))

                                if self.shouldDumpBlock(block):
                                        # Save to disk.
                                        print("--[DUMPING BLOCK…]--")
                                        block.dump(self.blockPath / (block.identifier.hex() + "." + FILE_EXT_NCLE), self.privateKey)
                                else:
                                        print("COULD NOT DUMP THIS BLOCK AT THIS TIME - STRONGER BLOCK EXISTS!")

                                block.bits = IdentityBlock.lowerTarget(block.bits)
                        else:
                                # It would be amazing if this point was ever reached.
                                print("COULD NOT FIND PROOF-OF-WORK!")
        
        # To be called on the genesis block, which is mined at max intensity.
        def powInit(self, block):
                if block is None:
                        raise ValueError("Fortifier.powInit(1): block is None")
                elif not isinstance(block, IdentityBlock):
                        raise TypeError("Fortifier.powInit(1): block is not an instance of IdentityBlock")
                
                block.timestampUpdated = datetime.now()
                hash = int(block.hash().hex(), base=16)

                target = block.unpackTarget()
                print(f"TARGET: {target[2]:#0{66}x}")
                print(f"TRYING {hash:#0{66}x}")
                counter = 0
                solved = False
                startTime = time.time()

                for nonce in range(MAX_NONCE):
                        if hash < target[2]:
                                solved = True
                                break
                        
                        block.timestampUpdated = datetime.now()
                        block.nonce = nonce
                        counter += 1
                        hash = int(block.hash().hex(), base=16)
                        print(f"{counter:,}: {hash:#0{66}x}")
                
                if not solved:
                        for nonce in range(MAX_NONCE):
                                if hash < target[2]:
                                        solved = True
                                        break
                                
                                block.timestampUpdated = datetime.now()
                                block.extraNonce = nonce
                                counter += 1
                                hash = int(block.hash().hex(), base=16)
                                print(f"{counter:,}: {hash:#0{66}x}")
                
                if solved:
                        elapsed = int(time.time() - startTime)
                        print(f"FOUND PROOF-OF-WORK AT {datetime.now()}!")
                        print("IT TOOK {:02d}:{:02d}:{:02d}".format(elapsed // 3600, (elapsed % 3600 // 60), elapsed % 60))

                        if self.shouldDumpBlock(block):
                                # Save to disk.
                                print("--[DUMPING BLOCK…]--")
                                block.dump(self.blockPath / (block.identifier.hex() + "." + FILE_EXT_NCLE), self.privateKey)
                        else:
                                print("COULD NOT DUMP THIS BLOCK AT THIS TIME - STRONGER BLOCK EXISTS!")

                        block.bits = IdentityBlock.lowerTarget(block.bits)
                        self.pow(block)
                else:
                        # It would be amazing if this point was ever reached.
                        print("COULD NOT FIND PROOF-OF-WORK!")
        
        def readConfig(self):
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

                with open(PATH_FORT_FILE_CONF, "r") as file:
                        configLines = file.read().strip().split("\n")
                        for line in configLines:
                                if not line.startswith(CONF_SYMBOL_COMMENT):
                                        config = line.split(" ", 1)
                                        key = config[0].strip()
                                        if key == CONF_KEY_INTENSITY:
                                                self.intensity = int(config[1].strip())
                                                if self.intensity > self.MAX_INTENSITY:
                                                        self.intensity = self.MAX_INTENSITY
                                                elif self.intensity <= 0:
                                                        self.intensity = 1
        
        def readIdentity(self):
                if self.isBlobMode:
                        with open(self.idPath, "rb") as idFile:
                                identifier = idFile.read()
                else:
                        with open(self.idPath, "r") as idFile:
                                identifier = idFile.read().strip().lower()  # Nomicle is case-insensitive when it comes to identifiers.
                return identifier
        
        def saveIdentity(self, rawIdentifier):
                if rawIdentifier is None:
                        raise ValueError("Fortifier.saveIdentity(1): rawIdentifier is None")
                
                with open(self.idPath, "w+") as idFile:
                        idFile.write(rawIdentifier)

        def shouldDumpBlock(self, block):
                if block is None:
                        raise ValueError("Fortifier.shouldDumpBlock(1): block is None")
                elif not isinstance(block, IdentityBlock):
                        raise TypeError("Fortifier.shouldDumpBlock(1): block is not an instance of IdentityBlock")

                existingInstance = IdentityBlock.read(Path(self.blockPath) / (block.identifier.hex() + "." + FILE_EXT_NCLE))
                if existingInstance is None:
                        return True
                else:
                        # Unpack the target of each block and compare.
                        newBlockExponent = (block.bits >> (8 * 3)) & 0xFF
                        newBlockMantissa = (block.bits >> (8 * 0)) & 0xFFFFFF
                        newBlockTarget = newBlockMantissa * (2**(0x08 * (newBlockExponent - 0x03)))

                        existingBlockExponent = (existingInstance.bits >> (8 * 3)) & 0xFF
                        existingBlockMantissa = (existingInstance.bits >> (8 * 0)) & 0xFFFFFF
                        existingBlockTarget = existingBlockMantissa * (2**(0x08 * (existingBlockExponent - 0x03)))
                        
                        if newBlockTarget < existingBlockTarget:
                                return True
                        else:
                                return False
        
        def start(self, rawIdentifier=None):
                sys.setrecursionlimit(10000)
                self.bootstrap()

                self.privateKey = self.loadPrivateKey()
                if self.privateKey is None:
                        self.privateKey = ec.generate_private_key(ec.SECP256K1(), default_backend())
                        self.dumpPrivateKey(self.privateKey)
                
                if rawIdentifier is not None:
                        self.saveIdentity(rawIdentifier)
                # This flag is for printing an alert to the console in case the ID file is empty.
                didAlert = False
                while 1:
                        self.userRawIdentifier = self.readIdentity()
                        self.userIdentifier = hashlib.sha256(self.userRawIdentifier.encode()).digest()
                        if self.userRawIdentifier is not None and len(self.userRawIdentifier) > 0:
                                token = hashlib.sha256(self.userRawIdentifier if self.isBlobMode else self.userRawIdentifier.encode()).hexdigest()
                                try:
                                        block = IdentityBlock.read(Path(self.blockPath) / (token + "." + FILE_EXT_NCLE))
                                        genesis = False
                                        
                                        if block is None:
                                                # No block file currently exists; make a new one.
                                                print("NO EXISTING BLOCK FOUND! GENERATING A NEW ONE…")
                                                block = IdentityBlock(
                                                                identifier=self.userRawIdentifier, 
                                                                publicKey=self.privateKey.public_key()
                                                        )
                                                genesis = True
                                        else:
                                                if block.publicKey.public_numbers() == self.privateKey.public_key().public_numbers():
                                                        # Decrease the target and start finding the new proof-of-work.
                                                        block.bits = IdentityBlock.lowerTarget(block.bits)
                                                else:
                                                        existingBits = block.bits
                                                        block = IdentityBlock(
                                                                identifier=self.userRawIdentifier, 
                                                                publicKey=self.privateKey.public_key()
                                                        )
                                                        block.bits = IdentityBlock.lowerTarget(existingBits)

                                        didAlert = False
                                        if genesis:
                                                # Genesis block is mined at max intensity.
                                                self.powInit(block)
                                        else:
                                                self.pow(block)
                                except Exception as e:
                                        print("Fortifier.start():", e)
                        else:
                                if not didAlert:
                                        print("NO IDENTITY TOKEN FOUND IN ID FILE!")
                                        didAlert = True
                                
                                time.sleep(self.INTERVAL_IDLE) # Otherwise this would consume too much CPU and power constantly checking a blank file.

if __name__ == "__main__":
        parser = argparse.ArgumentParser(description="This is the Foritifier program that is responsible for generating and fortifying identity blocks for the local user of the system.")
        parser.add_argument("-i", "--identifier", type=str, help="The Nomicle identifier you would like to use to identify yourself.")
        args = parser.parse_args()

        fortifier = Fortifier()
        fortifier.start(args.identifier)
