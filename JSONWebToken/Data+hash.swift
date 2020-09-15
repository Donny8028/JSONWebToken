//
//  Data+hash.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 19/05/2020.
//

import Foundation
import CommonCrypto

extension Data {
    func sha(_ hashFunction: SignatureAlgorithm.HashFunction) -> Data {
        return self.withUnsafeBytes { buffer -> Data in
            switch hashFunction {
            case .sha256:
                let result = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(CC_SHA256_DIGEST_LENGTH))
                defer { result.deallocate() }
                CC_SHA256(buffer.baseAddress, CC_LONG(buffer.count), result.baseAddress)
                return Data(buffer: result)
            case .sha384:
                let result = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(CC_SHA384_DIGEST_LENGTH))
                defer { result.deallocate() }
                CC_SHA384(buffer.baseAddress, CC_LONG(buffer.count), result.baseAddress)
                return Data(buffer: result)
            case .sha512:
                let result = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(CC_SHA512_DIGEST_LENGTH))
                defer { result.deallocate() }
                CC_SHA512(buffer.baseAddress, CC_LONG(buffer.count), result.baseAddress)
                return Data(buffer: result)
            }
        }
    }
    func hmac(_ hashFunction: SignatureAlgorithm.HashFunction, secret: Data) -> Data {
        return self.withUnsafeBytes { buffer -> Data in
            return secret.withUnsafeBytes { secretBuffer -> Data in
                let function: CCHmacAlgorithm
                let resultLen: Int32
                switch hashFunction {
                case .sha256:
                    function = CCHmacAlgorithm(kCCHmacAlgSHA256)
                    resultLen = CC_SHA256_DIGEST_LENGTH
                case .sha384:
                    function = CCHmacAlgorithm(kCCHmacAlgSHA384)
                    resultLen = CC_SHA384_DIGEST_LENGTH
                case .sha512:
                    function = CCHmacAlgorithm(kCCHmacAlgSHA512)
                    resultLen = CC_SHA512_DIGEST_LENGTH
                }
                let result = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(resultLen))
                defer { result.deallocate() }
                CCHmac(function, secretBuffer.baseAddress, secretBuffer.count, buffer.baseAddress, buffer.count, result.baseAddress)
                return Data(buffer: result)
            }
        }
    }
}
