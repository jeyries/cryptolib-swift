//
//  Cryptor.swift
//  CryptoLib
//
//  Created by Sebastian Stenzel on 25.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import Foundation

extension Data {
	
	public init?(base64UrlEncoded base64String: String, options: Data.Base64DecodingOptions = []) {
		self.init(base64Encoded: base64String.replacingOccurrences(of: "_", with: "/").replacingOccurrences(of: "-", with: "+"), options: options)
	}
	
	public func base64UrlEncodedString(options: Data.Base64EncodingOptions = []) -> String {
		return self.base64EncodedString(options: options).replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
	}
	
}

public enum FileNameEncoding {
	case base64url
}

public class Cryptor {
	
	private let masterKey: Masterkey
	
	public init(masterKey: Masterkey) {
		self.masterKey = masterKey;
	}
	
	// MARK: -
	// MARK: Path Encryption and Decryption:
	
	public func encryptFileName(cleartextName: String, directoryId: Data, encoding: FileNameEncoding = .base64url) -> String? {
		// encrypt:
		let cleartext = [UInt8](cleartextName.precomposedStringWithCanonicalMapping.utf8)
		guard let ciphertext = try? AesSiv.encrypt(aesKey: masterKey.aesMasterKey, macKey: masterKey.macMasterKey, plaintext: cleartext, ad: directoryId.bytes) else {
			return nil
		}
		
		// encode:
		switch encoding {
		case .base64url: return Data(ciphertext).base64UrlEncodedString()
		}
	}
	
	public func decryptFileName(ciphertextName: String, directoryId: Data, encoding: FileNameEncoding = .base64url) -> String? {
		// decode:
		let maybeCiphertextData : Data? = {
			switch encoding {
			case .base64url: return Data(base64UrlEncoded: ciphertextName)
			}
		}()
		guard let ciphertextData = maybeCiphertextData else {
			return nil
		}
		
		// decrypt:
		if let cleartext = try? AesSiv.decrypt(aesKey: masterKey.aesMasterKey, macKey: masterKey.macMasterKey, ciphertext: ciphertextData.bytes, ad: directoryId.bytes) {
			return String(data: Data(cleartext), encoding: .utf8)
		} else {
			return nil
		}
	}
	
	// MARK: -
	// MARK: File Content Encryption and Decryption
	
	func encryptSingleChunk(chunkNumber: UInt64, nonce: [UInt8], cleartext: [UInt8], fileKey: [UInt8]) -> [UInt8] {
		return [UInt8](); // TODO
	}
	
	func decryptSingleChunk(chunkNumber: UInt64, nonce: [UInt8], ciphertext: [UInt8], fileKey: [UInt8]) -> [UInt8] {
		return [UInt8](); // TODO
	}
	
}
