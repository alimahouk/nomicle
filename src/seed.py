#!/usr/bin/env python3

# seed.py | v0.1 | 23/08/2019 | by alimahouk
# ---------------------------------------------
# ABOUT THIS FILE
# ---------------------------------------------
# This is the Seeder program that is responsible for spreading identity blocks to
# other peers and handling probes for specific identity blocks.

import hashlib
import os
import random
import socket
import sys
import threading
import time
from datetime import datetime, timedelta
from distutils.util import strtobool
from enum import auto, IntEnum
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
CONF_KEY_INTENSITY = "intensity"
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
        PATH_NCLE_FILE_HOSTS = PATH_NCLE_DIR_DATA / "hosts.txt"
        PATH_NCLE_FILE_KEY = PATH_NCLE_DIR_CONF / "privkey.pem"
        PATH_NCLE_FILE_PROBES = PATH_NCLE_DIR_DATA / "probes.txt"
else:
        PATH_NCLE_DIR_DATA = Path("/usr/local/var/ncle")
        PATH_NCLE_DIR_COMMON = Path("/usr/local/share/ncle")
        PATH_NCLE_DIR_CONF = Path("/usr/local/etc/ncle")

        PATH_NCLE_DIR_BLOCKS = PATH_NCLE_DIR_DATA / "blocks"
        PATH_NCLE_FILE_CONF = PATH_NCLE_DIR_CONF / "ncle.conf"
        PATH_NCLE_FILE_ID = PATH_NCLE_DIR_COMMON / "id"
        PATH_NCLE_FILE_HOSTS = PATH_NCLE_DIR_DATA / "hosts"
        PATH_NCLE_FILE_KEY = PATH_NCLE_DIR_CONF / "privkey.pem"
        PATH_NCLE_FILE_PROBES = PATH_NCLE_DIR_DATA / "probes"
##########


# Returned as a result of comparing two identity blocks.
class IdentityBlockStatus(IntEnum):
        UNDEFINED = 0
        EXISTS = auto()                 # This is in cases where both blocks happen to be equally strong but each belongs to a different key.
        EXISTS_COPY = auto()
        INVALID_TIMESTAMP = auto()
        LOCAL_IDENTITY = auto()
        NOT_FOUND = auto()
        STRONG_ABOVE_THRESHOLD = auto()
        STRONG_BELOW_THRESHOLD = auto()
        WEAK = auto()


class Host():
        def __init__(self, address, port):
                self.address = address
                self.lastExchangeReceived = None
                self.lastExchangeSent = None
                self.lastProbed = None
                self.lastReached = None
                self.lastReachAttempt = None
                self.reachable = False

                if isinstance(port, str):
                        self.port = int(port)
                else:
                        self.port = port
        
        def __eq__(self, other):
                if isinstance(other, Host) and \
                   self.address == other.address and \
                   self.port == other.port:
                        return True
                else:
                        return False
        
        def __hash__(self):
                return hash(f"{self.address}:{self.port}")

        def __repr__(self):
                if self.reachable:
                        return f"[1] Host {self.address}:{self.port}"
                else:
                        return f"[0] Host {self.address}:{self.port}"

        def __str__(self):
                if self.reachable:
                        return f"[1] Host {self.address}:{self.port}"
                else:
                        return f"[0] Host {self.address}:{self.port}"


class ProtocolMessage():
        # PROTOCOL MESSAGE STRUCTURE
        ############################
        # 1) VERSION (1 byte)
        # ------------------------------------
        # 2) TYPE (1 byte)
        #-------------------------------------
        # 3) ERROR CODE (1 byte)
        #-------------------------------------
        # 4) BODY SIZE (8 bytes)
        #-------------------------------------
        # 5) BODY

        currentProtocolVersion = 0

        def __init__(self, data=None):
                if data is not None:
                        self.version = int.from_bytes(
                                data[:1], 
                                byteorder="big", 
                                signed=False
                                )
                        self.type = int.from_bytes(
                                data[1:2], 
                                byteorder="big", 
                                signed=False
                                )
                        self.errorCode = int.from_bytes(
                                data[2:3], 
                                byteorder="big", 
                                signed=False
                                )

                        bodySize = int.from_bytes(
                                data[3:11], 
                                byteorder="big", 
                                signed=False
                                )
                        if bodySize > 0:
                                self.body = bytes(data[11:11+bodySize])
                        else:
                                self.body = None
                else:
                        self.version = self.currentProtocolVersion
                        self.type = ProtocolMessageType.UNDEFINED
                        self.errorCode = 0
                        self.body = None

        def serialise(self):
                messageByteArray = bytearray()

                versionBytes = self.version.to_bytes(
                        1, 
                        byteorder="big", 
                        signed=False
                        )
                messageByteArray.extend(versionBytes)
                
                typeBytes = self.type.to_bytes(
                        1, 
                        byteorder="big", 
                        signed=False
                        )
                messageByteArray.extend(typeBytes)
                
                errorCodeBytes = self.errorCode.to_bytes(
                        1, 
                        byteorder="big", 
                        signed=False
                        )
                messageByteArray.extend(errorCodeBytes)
                
                # NOTE: body must be bytes!
                if self.body is not None:
                        bodySize = len(self.body)
                else:
                        bodySize = 0
                bodySizeBytes = bodySize.to_bytes(
                        8, 
                        byteorder="big", 
                        signed=False
                        )
                messageByteArray.extend(bodySizeBytes)

                if self.body is not None:
                        messageByteArray.extend(self.body)

                return messageByteArray


class ProtocolMessageType(IntEnum):
        UNDEFINED = 0
        HOST = auto()                   # • The IP address and port of a seeder instance.
        ID_PROBE = auto()               # • Sent to ask a peer if they have a particular identity block.
        ID_PROBE_RESPONSE = auto()      # • Sent in response to a probe.
        ID_SEED = auto()                # • Sent for seeding an identity block.
        PING = auto()                   # • Sent to check if a host is reachable.
        PONG = auto()                   # • Sent in response to a ping.


class Seeder:
        AGE_HOST = timedelta(days=15)           # Days after which an unreachable host gets purged
        DEFAULT_CONFIG_NCLE = f"""{CONF_KEY_BLOCK_PATH} {PATH_NCLE_DIR_BLOCKS}
{CONF_KEY_KEY_PATH} {PATH_NCLE_FILE_KEY}
{CONF_KEY_ID_PATH} {PATH_NCLE_FILE_ID}
{CONF_KEY_ID_BLOB} 0 """
        DEFAULT_HOSTS = {"35.176.210.85:1992"}
        INTERVAL_HOST_PING = 20                 # Seconds
        INTERVAL_POLL_USER_BLOCK = 5            # Seconds
        INTERVAL_POOL_EXCHANGE = 60 * 10        # Seconds
        INTERVAL_PROBE = 60 * 10                # Seconds
        OVERTAKE_PERCENTAGE = 1.0
        POOL_BLOCK_EXCHANGE_SIZE = 50
        POOL_HOST_EXCHANGE_SIZE = 100
        PORT_SEEDER = 1992

        def __init__(self, port=PORT_SEEDER):
                self.blockPath = PATH_NCLE_DIR_BLOCKS
                self.hosts = set()
                self.idPath = PATH_NCLE_FILE_ID
                self.isBlobMode = False                 # This means the program reads the identity file in binary mode (i.e. the file could contain anything).
                self.privateKey = None
                self.privateKeyPath = PATH_NCLE_FILE_KEY
                self.probes = set()
                self.userBlockLastMod = None
                self.userBlockPathName = None
                self.userIdentifier = None
                self.userRawIdentifier = None

                serverAddress = ("0.0.0.0", port)
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.setsockopt(
                        socket.SOL_SOCKET, 
                        socket.SO_REUSEADDR, 
                        1
                        )
                self.sock.bind(serverAddress)
        
        def blockPool(self):
                # Return a random batch of identity blocks.
                files = [filename for filename in os.listdir(self.blockPath) if os.path.isfile(self.blockPath / filename) and filename[0] != "."]
                batch = random.sample(files, min(self.POOL_BLOCK_EXCHANGE_SIZE, len(files)))
                pool = []
                for blockFilePath in batch:
                        block = self.readBlock(blockFilePath)
                        if block is not None:
                                pool.append(block)
                return pool
        
        def bootstrap(self):
                # Integrity checks.
                self.checkDirs()
                # Start with the config file to determine where some things ought to go.
                self.checkConfigFile()
                self.readConfig()

                self.checkIdentityBlockPool()
                self.checkHostsFile()
                self.checkIdentityFile()
                self.checkProbesFile()
                # Load the host list.
                self.readHosts()

        def broadcast(self, message, excluding=None):
                for host in self.hosts:
                        if excluding is None or (excluding is not None and host not in excluding):
                                self.sendMessage(host, message)
        
        def checkConfigFile(self):
                if not os.path.exists(PATH_NCLE_FILE_CONF):
                        with open(PATH_NCLE_FILE_CONF, "w+") as newFile:
                                newFile.write(self.DEFAULT_CONFIG_NCLE)

        def checkDirs(self):
                if not os.path.exists(PATH_NCLE_DIR_CONF):
                        PATH_NCLE_DIR_CONF.mkdir(parents=True)
                if not os.path.exists(PATH_NCLE_DIR_COMMON):
                        PATH_NCLE_DIR_COMMON.mkdir(parents=True)
                if not os.path.exists(PATH_NCLE_DIR_DATA):
                        PATH_NCLE_DIR_DATA.mkdir(parents=True)

        def checkIdentityBlockPool(self):
                if not os.path.exists(self.blockPath):
                        self.blockPath.mkdir(parents=True)

        def checkIdentityFile(self):
                if not os.path.exists(self.idPath):
                        with open(self.idPath, "w+") as newFile:
                                newFile.write("")

        def checkHostsFile(self):
                if not os.path.exists(PATH_NCLE_FILE_HOSTS):
                        fileContents = "\n".join(self.DEFAULT_HOSTS)

                        with open(PATH_NCLE_FILE_HOSTS, "w+") as newFile:
                                newFile.write(fileContents)

        def checkProbe(self, identifier):
                exists = False
                for i in self.probes:
                        if i == identifier:
                                exists = True
                                break
                if exists:
                        self.probes.discard(identifier)
                        self.dumpProbes()
                
                return exists
        
        def checkProbesFile(self):
                if not os.path.exists(PATH_NCLE_FILE_PROBES):
                        newFile = open(PATH_NCLE_FILE_PROBES, "w+")
                        newFile.write("")

        def dumpHosts(self):
                fileContents = ""
                for host in self.hosts:
                        line = f"{host.address}:{host.port}"
                        if host.lastReached is not None:
                                line += f" {int(host.lastReached.timestamp())}"
                        if host.lastReachAttempt is not None:
                                line += f" {int(host.lastReachAttempt.timestamp())}"
                        line += "\n"
                        fileContents += line

                with open(PATH_NCLE_FILE_HOSTS, "w+") as hostsFile:
                        hostsFile.write(fileContents)

        def dumpProbes(self):
                fileContents = ""
                for identifier in self.probes:
                        line = f"{identifier}\n"
                        fileContents += line
                
                with open(PATH_NCLE_FILE_PROBES, "w+") as probesFile:
                        probesFile.write(fileContents)

        def exchangeBlockPool(self, host, target=None):
                if not host.reachable:
                        return

                # Pools are exchanged at intervals.
                now = datetime.now()
                pool = []
                if host.lastExchangeSent is None or \
                   now - timedelta(seconds=self.INTERVAL_POOL_EXCHANGE) > host.lastExchangeSent <= now:
                        # Put together a batch.
                        pool.extend(self.blockPool())
                        # Update the last-exchange timestamp for this host.
                        host.lastExchangeSent = datetime.now()
                
                # If a target is specified and it's in the local repo, include it in the batch.
                if target is not None:
                        print(f"PEER PROBING FOR {target}…")
                        targetBlockFilePath = self.blockPath / target + "." + FILE_EXT_NCLE
                        if os.path.exists(targetBlockFilePath):
                                print(f"FOUND!")
                                targetBlock = self.readBlock(target)
                                pool.append(targetBlock)
                        else:
                                print(f"NOT FOUND.")
                # Send them off.
                for block in pool:
                        message = ProtocolMessage()
                        message.type = ProtocolMessageType.ID_SEED
                        message.body = block
                        self.sendMessage(host, message)
        
        def exchangeHostPool(self, host):
                if not host.reachable:
                        return
                
                batch = random.sample(self.hosts, min(self.POOL_HOST_EXCHANGE_SIZE, len(self.hosts)))
                for server in batch:
                        # Don't send a dead host.
                        #
                        # NOTE: server.lastReachAttempt is always >= server.lastReached
                        # because it is updated whenever a message is received from the
                        # host as well as when a message is sent to it.
                        if server.lastReachAttempt - server.lastReached <= self.AGE_HOST:
                                messageBody = f"{server.address}:{server.port}"
                                if server.lastReached is not None:
                                        messageBody += f" {int(server.lastReached.timestamp())}"
                                if server.lastReachAttempt is not None:
                                        messageBody += f" {int(server.lastReachAttempt.timestamp())}"

                                message = ProtocolMessage()
                                message.type = ProtocolMessageType.HOST
                                message.body = messageBody.encode()
                                self.sendMessage(host, message)

        def listenForSeeders(self):
                while 1:
                        # NOTE:
                        # -----
                        # This probably needs to be modified to recv messages of arbitrary sizes.
                        message, address = self.sock.recvfrom(1024)
                        # Ignore our own LAN broadcast messages.
                        if address[0] != self.localAddress():
                                now = datetime.now()
                                host = Host(address[0], address[1])
                                host.lastReached = now
                                host.lastReachAttempt = now
                                host.reachable = True
        
                                self.routeMessage(message, host)
                        
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
        
        def localAddress(self):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                        # Doesn't even have to be reachable.
                        sock.connect(("10.255.255.255", 1))
                        address = sock.getsockname()[0]
                except Exception:
                        address = "127.0.0.1"
                finally:
                        sock.close()
                return address
        
        def localBroadcast(self):
                message = ProtocolMessage()
                message.type = ProtocolMessageType.PING
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                try:
                        self.sock.sendto(message.serialise(), ("255.255.255.255", self.PORT_SEEDER))
                except Exception as e:
                        print(e)
                # Turn off the broadcast flag.
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)
                
        def parseHosts(self, hostLines):
                for hostLine in hostLines:
                        lineParts = hostLine.strip().split(" ")
                        if len(lineParts) > 0:
                                # Each line can contain an IP address, a port (concatenated by a colon), 
                                # and a space followed by the last time that the host was reachable and
                                # the last time reachability was attempted.
                                host = None
                                hostAddress = lineParts[0]
                                addressParts = hostAddress.split(":")
                                now = datetime.now()

                                if len(addressParts) == 2:
                                        address = addressParts[0]
                                        port = int(addressParts[1])
                                        # Check if one of the default hosts is the current machine
                                        # in which case don't add it to the set.
                                        if address != self.localAddress():
                                                host = Host(address, port)

                                if host is not None:
                                        if len(lineParts) == 3:
                                                host.lastReached = datetime.fromtimestamp(int(lineParts[1]))
                                                host.lastReachAttempt = datetime.fromtimestamp(int(lineParts[2]))
                                        elif len(lineParts) == 2:
                                                host.lastReached = datetime.fromtimestamp(int(lineParts[1]))
                                        else:
                                                # Set the lastReached time to now to give us something
                                                # to guage reachability in the future for cleaning up.
                                                host.lastReached = now
                                                host.lastReachAttempt = now
                                        
                                        self.hosts.add(host)
        
        def pingHosts(self):
                # Broadcast once to discover hosts on our LAN.
                self.localBroadcast()

                while 1:
                        # Make a list copy of the set to allow for mutation.
                        for host in list(self.hosts):
                                now = datetime.now()
                                # No use pinging a peer again if they just pinged us. Allow for a gap.
                                if host.lastReached is None or \
                                   now - timedelta(seconds=self.INTERVAL_HOST_PING) > host.lastReached <= now:
                                        print(f"--[PINGING {host.address}:{host.port}]--")
                                        message = ProtocolMessage()
                                        message.type = ProtocolMessageType.PING
                                        self.sendMessage(host, message)
                                
                                # If a host hasn't responded to a ping for a duration more than three intervals
                                # then they're likely unreachable.
                                if host.reachable and \
                                   now - timedelta(seconds=self.INTERVAL_HOST_PING*3) > host.lastReached <= now:
                                        print(f"--[{host} IS UNREACHABLE]--")
                                        host.reachable = False
                                
                                # Check if this is a dead host.
                                if now - host.lastReached > self.AGE_HOST:
                                        print(f"--[{host} IS DEAD]--")
                                        self.hosts.discard(host)
                        
                        # Dump the set to the disk.
                        self.dumpHosts()
                        time.sleep(self.INTERVAL_HOST_PING)
                        if len(self.hosts) == 0:
                                # Continuously broadcast if we have no known peers.
                                self.localBroadcast()
        
        def pollBlock(self):
                if self.privateKey is not None:
                        self.userRawIdentifier = self.readIdentity()

                        if self.userRawIdentifier is not None and len(self.userRawIdentifier) > 0:
                                self.userIdentifier = hashlib.sha256(self.userRawIdentifier.encode()).digest()
                                blockFilePath = self.blockPath / (self.userIdentifier.hex() + "." + FILE_EXT_NCLE)
                        else:
                                self.userIdentifier = None
                                self.userRawIdentifier = None
                                blockFilePath = None

                        while 1:
                                if blockFilePath is not None and os.path.exists(blockFilePath):
                                        modDate = datetime.fromtimestamp(os.path.getmtime(blockFilePath))
                                        if self.userBlockLastMod is not None and modDate != self.userBlockLastMod:
                                                # Timestamp has been modified. Check the key inside the block to
                                                # make sure this block belongs to the local user.
                                                block = IdentityBlock.read(blockFilePath)
                                                if block.publicKey.public_numbers() == self.privateKey.public_key().public_numbers():
                                                        print("--[MOFIFIED LOCAL IDENTITY BLOCK DETECTED]--")
                                                        self.seedBlock(self.userIdentifier.hex())

                                        self.userBlockLastMod = modDate

                                self.pollProbes()
                                time.sleep(self.INTERVAL_POLL_USER_BLOCK)

        def pollProbes(self):
                now = datetime.now()

                self.readProbes()
                for identifier in self.probes:
                        message = ProtocolMessage()
                        message.type = ProtocolMessageType.ID_PROBE
                        message.body = identifier.encode()
                        
                        for host in self.hosts:
                                if host.reachable and \
                                  (host.lastProbed is None or \
                                   now - timedelta(seconds=self.INTERVAL_PROBE) > host.lastProbed <= now):
                                        host.lastProbed = now
                                        self.sendMessage(host, message)
        
        def processHost(self, hostStr):
                if hostStr is None:
                        raise ValueError("Seeder.processHost(1): hostStr is None")
                
                lineParts = hostStr.strip().split(" ")
                if len(lineParts) > 0:
                        # Each line can contain an IP address, a port (concatenated by a colon), 
                        # and a space followed by the last time that the host was reachable and
                        # the last time reachability was attempted.
                        host = None
                        hostAddress = lineParts[0]
                        addressParts = hostAddress.split(":")
                        now = datetime.now()

                        if len(addressParts) == 2:
                                address = addressParts[0]
                                port = int(addressParts[1])
                                # Check if one of the default hosts is the current machine
                                # in which case don't add it to the set.
                                if address != self.localAddress():
                                        host = Host(address, port)

                        if host is not None:
                                if len(lineParts) == 3:
                                        host.lastReached = datetime.fromtimestamp(int(lineParts[1]))
                                        host.lastReachAttempt = datetime.fromtimestamp(int(lineParts[2]))
                                elif len(lineParts) == 2:
                                        host.lastReached = datetime.fromtimestamp(int(lineParts[1]))
                                else:
                                        # Set the lastReached time to now to give us something
                                        # to guage reachability in the future for cleaning up.
                                        host.lastReached = now
                                        host.lastReachAttempt = now

                                hostExists = False
                                for host in self.hosts:
                                        if host == host:
                                                hostExists = True
                                                break
                                if not hostExists:
                                        self.hosts.add(host)

        def readBlock(self, blockHash):
                if blockHash is None:
                        raise ValueError("Seeder.readBlock(1): blockHash is None")
                elif not isinstance(blockHash, str):
                        raise TypeError("Seeder.readBlock(1): blockHash is not an instance of str")

                # NOTE:
                # This method is not equivalent to IdentityBlock.read(1), which returns an IdentityBlock object.
                # This method only returns the raw byte array of a block as it reads it from the file.
                try:
                        blockFilename = blockHash
                        if not blockFilename.endswith("." + FILE_EXT_NCLE): # Append the file extension if it's missing.
                                blockFilename = blockFilename + "." + FILE_EXT_NCLE

                        blockFilePath = self.blockPath / blockFilename
                        with open(blockFilePath, mode="rb") as file:
                                return bytearray(file.read())
                except EnvironmentError:
                        return None

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

        def readHosts(self):
                with open(PATH_NCLE_FILE_HOSTS) as hostsFile:
                        # Clear the current set.
                        self.hosts.clear()
                        self.parseHosts(hostsFile)
                        
                        if len(self.hosts) == 0:
                                # Use the hard-coded known hosts.
                                self.parseHosts(self.DEFAULT_HOSTS)

        def readIdentity(self):
                if self.isBlobMode:
                        with open(self.idPath, "rb") as file:
                                identifier = file.read()
                else:
                        with open(self.idPath, "r") as file:
                                identifier = file.read().strip().lower()  # Nomicle is case-insensitive when it comes to identifiers.
                return identifier

        def readProbes(self):
                with open(PATH_NCLE_FILE_PROBES) as probesFile:
                        self.probes.clear()
                        for probe in probesFile:
                                probe = probe.strip()
                                if len(probe) > 0:
                                        self.probes.add(probe.strip())
        
        def routeMessage(self, message, sender):
                if message is None:
                        raise ValueError("Messenger.routeMessage(2): message is None")
                
                message = ProtocolMessage(data=message)
                if message.type == ProtocolMessageType.HOST:
                        if message.body is not None:
                                self.processHost(message.body.decode())
                elif message.type == ProtocolMessageType.ID_PROBE:
                        # The body of this message type is just the identifier in question as an 
                        # encoded string.
                        if message.body is not None:
                                target = message.body.decode()
                                for host in self.hosts:
                                        if host == sender:
                                                self.exchangeBlockPool(host, target)
                elif message.type == ProtocolMessageType.ID_SEED:
                        block = IdentityBlock.deserialise(message.body)
                        # Update the last-exchange timestamp for this host.
                        for host in self.hosts:
                                if host == sender:
                                        host.lastExchangeReceived = datetime.now()
                        if block is not None:
                                print(f"--[RECEIVED IDENTITY BLOCK OF {block.identifier.hex()}]--")
                                blockStatus = self.shouldAcceptBlock(block)
                                if blockStatus == IdentityBlockStatus.NOT_FOUND or \
                                   blockStatus == IdentityBlockStatus.STRONG_ABOVE_THRESHOLD:
                                        print("--[BLOCK ACCEPTED]--")
                                        # Check if this ID was being probed for.
                                        self.checkProbe(block.identifier.hex())
                                        block.dump(self.blockPath / (block.identifier.hex() + "." + FILE_EXT_NCLE))
                                        # Forward it to other peers.
                                        self.seedBlock(block.identifier.hex(), excluding=[sender])
                                else:
                                        if blockStatus == IdentityBlockStatus.WEAK or \
                                           blockStatus == IdentityBlockStatus.STRONG_BELOW_THRESHOLD:
                                                # Send back our stronger version of this block.
                                                existingInstance = IdentityBlock.read(self.blockPath / (block.identifier.hex() + "." + FILE_EXT_NCLE))
                                                if existingInstance is not None:
                                                        print("--[SENDING BACK STRONGER VERSION]--")
                                                        response = ProtocolMessage()
                                                        response.type = ProtocolMessageType.ID_SEED
                                                        response.body = existingInstance.serialise()
                                                        self.sendMessage(sender, response)
                                        elif blockStatus == IdentityBlockStatus.EXISTS_COPY:
                                                print("--[EXISTING COPY]--")
                elif message.type == ProtocolMessageType.PING:
                        hostExists = False
                        for host in self.hosts:
                                if host == sender:
                                        sender = host
                                        hostExists = True
                                        break
                        if not hostExists:
                                print(f"--[PINGED BY NEW {sender}]--")
                                self.hosts.add(sender)
                        # Update the reachability of the host.
                        if not sender.reachable:
                                sender.reachable = True
                                print(f"--[{sender} IS REACHABLE]--")
                                # Seed host IP addresses.
                                self.exchangeHostPool(sender)
                        # Send a pong.
                        response = ProtocolMessage()
                        response.type = ProtocolMessageType.PONG
                        self.sendMessage(sender, response)
                        # Next, send some blocks.
                        self.exchangeBlockPool(sender)
                elif message.type == ProtocolMessageType.PONG:
                        hostExists = False
                        for host in self.hosts:
                                if host == sender:
                                        host.lastReached = sender.lastReached
                                        host.lastReachAttempt = sender.lastReachAttempt
                                        sender = host
                                        hostExists = True
                                        break
                        if not hostExists:
                                print(f"--[FOUND NEW {sender}]--")
                                self.hosts.add(sender)
                        # Update the reachability of the host.
                        if not sender.reachable:
                                sender.reachable = True
                                print(f"--[{sender} IS REACHABLE]--")
                                # Seed host IP addresses.
                                self.exchangeHostPool(sender)
                        # Send some blocks.
                        self.exchangeBlockPool(sender)
                
        def seedBlock(self, identifier, excluding=None):
                if identifier is None:
                        raise ValueError("Seeder.seedBlock(2): identifier is None")
                elif not isinstance(identifier, str):
                        raise TypeError("Seeder.seedBlock(2): identifier is not an instance of str")

                block = self.readBlock(identifier)
                if block is not None:
                        message = ProtocolMessage()
                        message.type = ProtocolMessageType.ID_SEED
                        message.body = block
                        self.broadcast(message, excluding=excluding)

        def sendMessage(self, host, message):
                if host is None:
                        raise ValueError("Seeder.sendMessage(2): host is None")
                elif message is None:
                        raise ValueError("Seeder.sendMessage(2): message is None")
                
                try:
                        host.lastReachAttempt = datetime.now()
                        self.sock.sendto(message.serialise(), (host.address, host.port))
                except Exception as e:
                        print(e)
        
        def shouldAcceptBlock(self, block):
                if block is None:
                        raise ValueError("Seeder.shouldAcceptBlock(1): block is None")
                elif not isinstance(block, IdentityBlock):
                        raise TypeError("Seeder.shouldAcceptBlock(1): block is not an instance of IdentityBlock")

                existingInstance = IdentityBlock.read(self.blockPath / (block.identifier.hex() + "." + FILE_EXT_NCLE))
                if existingInstance is None:
                        return IdentityBlockStatus.NOT_FOUND
                else:
                        # Check the timestamp. A block set more than 2 hours into the future is rejected.
                        now = datetime.now()
                        if block.timestampCreated > now + timedelta(hours=2) or block.timestampCreated > block.timestampUpdated:
                                print("IDENTITY BLOCK CREATION TIMESTAMP IS TOO FAR INTO THE FUTURE")
                                return IdentityBlockStatus.INVALID_TIMESTAMP
                        if block.timestampUpdated > now + timedelta(hours=2):
                                print("IDENTITY BLOCK UPDATE TIMESTAMP IS TOO FAR INTO THE FUTURE")
                                return IdentityBlockStatus.INVALID_TIMESTAMP
                        
                        blockComparisonResult = IdentityBlock.compare(block, existingInstance)
                        if blockComparisonResult == -1:
                                # New block is stronger but does it satisfy overtaking rules?
                                # --
                                # 1) Target must be a certain percentage lower (not simply less than) 
                                #    than the existing instance.
                                # 2) The existing instance must not be overwritten if it is the local
                                #    user's block in order to give them a chance to fortify it and
                                #    perhaps claim ownership eventually.
                                targetNew = block.unpackTarget()
                                targetExisting = existingInstance.unpackTarget()
                                percentage = int(targetExisting[2] * (self.OVERTAKE_PERCENTAGE / 100))
                                threshold = targetExisting[2] - percentage

                                if targetNew[2] < threshold:
                                        if existingInstance.identifier == self.userIdentifier and \
                                           self.privateKey is not None and \
                                           existingInstance.publicKey.public_numbers() == self.privateKey.public_key().public_numbers():
                                                return IdentityBlockStatus.LOCAL_IDENTITY
                                        else:
                                                return IdentityBlockStatus.STRONG_ABOVE_THRESHOLD
                                else:
                                        return IdentityBlockStatus.STRONG_BELOW_THRESHOLD
                        elif blockComparisonResult == 1:
                                return IdentityBlockStatus.WEAK
                        else:
                                if block.publicKey.public_numbers() == existingInstance.publicKey.public_numbers():
                                        return IdentityBlockStatus.EXISTS_COPY
                                else:
                                        return IdentityBlockStatus.EXISTS

        def start(self):
                sys.setrecursionlimit(10000)
                self.bootstrap()

                self.userRawIdentifier = self.readIdentity()
                if self.userRawIdentifier is not None and len(self.userRawIdentifier) > 0:
                        self.userIdentifier = hashlib.sha256(self.userRawIdentifier.encode()).digest()
                else:
                        self.userIdentifier = None
                        self.userRawIdentifier = None

                self.privateKey = self.loadPrivateKey()

                # Maintain peer heartbeats on a separate thread.
                pingingThread = threading.Thread(target=self.pingHosts)
                pingingThread.daemon = True
                pingingThread.start()

                # Poll the filesystem for the user's block and the probe list on a separate thread.
                pollingThread = threading.Thread(target=self.pollBlock)
                pollingThread.daemon = True
                pollingThread.start()
                
                # This final method call is blocking.
                self.listenForSeeders()


if __name__ == "__main__":
        seeder = Seeder()
        seeder.start()
