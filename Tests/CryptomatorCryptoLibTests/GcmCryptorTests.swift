//
//  GcmCryptorTests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Sebastian Stenzel on 20.05.22.
//  Copyright © 2022 Skymatic GmbH. All rights reserved.
//

import XCTest
@testable import CryptomatorCryptoLib

class GcmCryptorTests: CryptorTests {
	override class var defaultTestSuite: XCTestSuite {
		return XCTestSuite(forTestCaseClass: GcmCryptorTests.self)
	}

	override func setUpWithError() throws {
		let aesKey = [UInt8](repeating: 0x55, count: 32)
		let macKey = [UInt8](repeating: 0x77, count: 32)
		let masterkey = Masterkey.createFromRaw(aesMasterKey: aesKey, macMasterKey: macKey)
		let cryptoSupport = CryptoSupportMock()
		let contentCryptor = GcmContentCryptor()

		try super.setUpWithError(masterkey: masterkey, cryptoSupport: cryptoSupport, contentCryptor: contentCryptor)
	}

	func testCreateHeader() throws {
		let header = try cryptor.createHeader()
		XCTAssertEqual([UInt8](repeating: 0xF0, count: 12), header.nonce)
		XCTAssertEqual([UInt8](repeating: 0xF0, count: 32), header.contentKey)
	}

	func testEncryptHeader() throws {
		let header = try cryptor.createHeader()
		let encrypted = try cryptor.encryptHeader(header)

		// echo -n "///////////w8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8A==" | base64 --decode \
		// | openssl enc -aes-256-gcm -K 5555555555555555555555555555555555555555555555555555555555555555 -iv F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0 -a
		let expected: [UInt8] = [
			// nonce
			0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
			0xF0, 0xF0, 0xF0, 0xF0,
			// ciphertext
			0x1C, 0x87, 0x19, 0xF0, 0x31, 0x22, 0x86, 0x8F,
			0xDB, 0x9D, 0x97, 0x03, 0xA0, 0x86, 0x08, 0xD5,
			0x88, 0x58, 0x96, 0xC2, 0xE6, 0x60, 0x4B, 0xB9,
			0xEA, 0x64, 0x31, 0xD4, 0xA0, 0x5D, 0x47, 0x6F,
			0xE4, 0x1F, 0x32, 0x31, 0xF2, 0xC0, 0x61, 0x1F,
			// tag
			0x6D, 0x42, 0x98, 0x82, 0x43, 0xF2, 0x1F, 0x43,
			0xF6, 0x44, 0xFD, 0x6D, 0xF7, 0xA9, 0x3F, 0x0B
		]
		XCTAssertEqual(expected, encrypted)
	}

	func testDecryptHeader() throws {
		let ciphertext: [UInt8] = [
			// nonce
			0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
			0xF0, 0xF0, 0xF0, 0xF0,
			// ciphertext
			0x1C, 0x87, 0x19, 0xF0, 0x31, 0x22, 0x86, 0x8F,
			0xDB, 0x9D, 0x97, 0x03, 0xA0, 0x86, 0x08, 0xD5,
			0x88, 0x58, 0x96, 0xC2, 0xE6, 0x60, 0x4B, 0xB9,
			0xEA, 0x64, 0x31, 0xD4, 0xA0, 0x5D, 0x47, 0x6F,
			0xE4, 0x1F, 0x32, 0x31, 0xF2, 0xC0, 0x61, 0x1F,
			// tag
			0x6D, 0x42, 0x98, 0x82, 0x43, 0xF2, 0x1F, 0x43,
			0xF6, 0x44, 0xFD, 0x6D, 0xF7, 0xA9, 0x3F, 0x0B
		]
		let decrypted = try cryptor.decryptHeader(ciphertext)
		XCTAssertEqual([UInt8](repeating: 0xF0, count: 12), decrypted.nonce)
		XCTAssertEqual([UInt8](repeating: 0xF0, count: 32), decrypted.contentKey)
	}

	func testDecryptSingleChunk() throws {
		let headerNonce: [UInt8] = [
			0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
			0x55, 0x55, 0x55, 0x55
		]
		let fileKey: [UInt8] = [
			0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
			0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
			0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
			0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77
		]
		let ciphertext: [UInt8] = [
			// nonce
			0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
			0x55, 0x55, 0x55, 0x55,
			// payload
			0x52, 0xC5, 0xEE, 0x8D, 0x7F, 0xB4, 0x4E, 0xF2,
			0x8A, 0xEC, 0x55,
			// tag
			0x3C, 0xC7, 0x02, 0x65, 0xE5, 0x35, 0x2C, 0xB5,
			0xA0, 0x9A, 0x43, 0xAE, 0x0F, 0x5C, 0xA1, 0x5D
		]

		let cleartext = try cryptor.decryptSingleChunk(ciphertext, chunkNumber: 0, headerNonce: headerNonce, fileKey: fileKey)

		XCTAssertEqual([UInt8]("hello world".utf8), cleartext)
	}
}