//
//  Nomicle.swift
//  libswiftnomicle
//
//  Created by alimahouk on 10/11/2020.
//

import OpenSSL

let NCLE_BITS_BASE = 0x1f00ffff
let NCLE_CHECKSUM_LEN = 8
let NCLE_ID_VERSION = 1
let NCLE_MAGIC_NUM = [0x89, 0x50, 0x44, 0x48, 0x5a, 0x0d, 0x0a, 0x1a, 0x0a]
let NCLE_TOKEN_LEN = 32

public class Nomicle {
        public var bits: UInt32 = 0
        public var extraNonce: UInt64 = 0
        public var hash: [UInt8]?
        public var nonce: UInt64 = 0
        public var publicKey: EVP_PKEY?
        public var signature: ECDSA_SIG?
        public var token: [UInt8]?
        public var timestampCreated: Int64 = 0
        public var timestampUpdated: Int64 = 0
        public var version: UInt8 = 0
        
        public static func compare(block1: Nomicle, block2: Nomicle) -> Int
        {
                // These return a tuple. The target is the third item.
                let unpack1 = block1.unpackTarget()
                let unpack2 = block2.unpackTarget()
                
                return Int(BN_cmp(unpack1.2, unpack2.2))
        }
        
        public static func deserialise(blockByteArray: [UInt8]) -> Nomicle
        {
                
        }
        
        public func dump(path: String, privateKey: EVP_PKEY?)
        {
                
        }
        
        public func blockHash() -> [UInt8]
        {
                /*
                 * We pack everything from the block into a buffer
                 * excluding the magic number, signature,
                 * and the hash itself (obviously).
                 */
                let key = Nomicle.encodeKey(publicKey!)
                var offset = 0
                let len = key.count + NCLE_TOKEN_LEN + MemoryLayout<UInt8>.size         /* Version */
                        + MemoryLayout<UInt32>.size                                     /* Bits */
                        + MemoryLayout<UInt64>.size                                     /* Nonce */
                        + MemoryLayout<UInt64>.size                                     /* Extra nonce */
                        + MemoryLayout<Int64>.size                                      /* Timestamp Created */
                        + MemoryLayout<Int64>.size                                      /* Timestamp Updated */
                        + MemoryLayout<UInt16>.size;                                    /* Public key size */
                let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: len)
                pointer.initialize(repeating: 0,
                                   count: len)
                defer {
                        pointer.deinitialize(count: len)
                        pointer.deallocate()
                }
                
                /* 1) Protocol version */
                pointer.pointee = UInt8(version & 0xff)
                offset += MemoryLayout<UInt16>.size
                /* 2) Identity token hash */
                token.copyBytes(to: pointer,
                                count: token.count)
                offset += token!.count * MemoryLayout<UInt8>.size
                
        }
        
        public static func read(path: String) -> Nomicle
        {
                
        }
        
        public func serialise(privateKey: EVP_PKEY?) -> [UInt8]
        {
                
        }
        
        public static func sign(blockHash: [UInt8], privateKey: EVP_PKEY) -> ECDSA_SIG?
        {
                let keyPointer = UnsafeMutablePointer<EVP_PKEY>.allocate(capacity: 1)
                keyPointer.initialize(to: privateKey)
                defer {
                        keyPointer.deinitialize(count: 1)
                        keyPointer.deallocate()
                }
                
                let ECKey = EVP_PKEY_get1_EC_KEY(keyPointer)
                let sigPointer = ECDSA_do_sign(blockHash, Int32(blockHash.count), ECKey)
                return sigPointer?.pointee
        }
        
        public func unpackTarget() -> (UInt32, UInt32, UnsafeMutablePointer<BIGNUM>?)
        {
                let exponent = (self.bits >> (8 * 3)) & 0xff
                let mantissa = (self.bits >> (8 * 0)) & 0xffffff
                
                let ctx = BN_CTX_new()
                let mantissaBN = Nomicle.uitobn(UInt(mantissa))
                let powBaseBN = Nomicle.uitobn(2)
                let powExponentBN = Nomicle.uitobn(UInt(0x08) * UInt(exponent - 0x03))
                var powResultBN: UnsafeMutablePointer<BIGNUM>?
                let target = BN_new()
                
                BN_exp(powResultBN, powBaseBN, powExponentBN, ctx)
                BN_mul(target, mantissaBN, powResultBN, ctx)
                
                return (exponent, mantissa, target)
        }
        
        private static func encodeKey(_ pKey: EVP_PKEY) -> [UInt8]
        {
                let keyPointer = UnsafeMutablePointer<EVP_PKEY>.allocate(capacity: 1)
                keyPointer.initialize(to: pKey)
                defer {
                        keyPointer.deinitialize(count: 1)
                        keyPointer.deallocate()
                }
                let bufferLen = i2d_PUBKEY(keyPointer, nil)
                var buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(bufferLen))
                buffer.initialize(repeating: 0,
                                  count: Int(bufferLen))
                defer {
                        buffer.deinitialize(count: 1)
                        buffer.deallocate()
                }
                
                var pointer: UnsafeMutablePointer<UInt8>? = buffer
                i2d_PUBKEY(keyPointer, &pointer)
                let tmp = UnsafeMutableBufferPointer(start: pointer,
                                                     count: Int(bufferLen))
                return Array(tmp)
        }
        
        private static func SHA(_ data: [UInt8]) -> [UInt8]
        {
                var buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(SHA256_DIGEST_LENGTH))
                buffer.initialize(repeating: 0,
                                  count: Int(SHA256_DIGEST_LENGTH))
                defer {
                        buffer.deinitialize(count: 1)
                        buffer.deallocate()
                }
                SHA256(data, data.count, buffer)
                let tmp = UnsafeMutableBufferPointer(start: buffer,
                                                     count: Int(SHA256_DIGEST_LENGTH))
                return Array(tmp)
        }
        
        private static func uitobn(_ i: UInt) -> UnsafeMutablePointer<BIGNUM>?
        {
                let str = String(i)
                var bn: UnsafeMutablePointer<UnsafeMutablePointer<BIGNUM>?>?
                BN_dec2bn(bn, str)
                
                return bn?.pointee
        }
}
