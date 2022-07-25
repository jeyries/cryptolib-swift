//
//  Cryptor+Streams.swift
//  CryptomatorCryptoLib
//
//  Created by Julien Eyriès on 26/07/2022.
//

import Foundation

// MARK: - Streams

public extension Cryptor {
	func decryptInputStream(wrapped: InputStream) -> InputStream {
		return CryptorDecryptInputStream(cryptor: self, wrapped: wrapped)
	}

	func encryptOutputStream(wrapped: OutputStream) -> OutputStream {
		return CryptorEncryptOutputStream(cryptor: self, wrapped: wrapped)
	}

	static func copyStream(inputStream: InputStream, outputStream: OutputStream) throws {
		inputStream.schedule(in: .current, forMode: .default)
		inputStream.open()
		defer { inputStream.close() }

		outputStream.schedule(in: .current, forMode: .default)
		outputStream.open()
		defer { outputStream.close() }

		var buffer = [UInt8](repeating: 0x00, count: 4096)

		while true {
			let readLength = inputStream.read(&buffer, maxLength: buffer.count)
			if let error = inputStream.streamError {
				throw error
			}
			if readLength <= 0 {
				break
			}

			let writeLength = outputStream.writeFully(buffer, maxLength: readLength)
			if let error = outputStream.streamError {
				throw error
			}
			if writeLength <= 0 {
				break
			}
		}
	}
}

final class CryptorDecryptInputStream: InputStream {
	private let cryptor: Cryptor
	private let wrapped: InputStream
	private var error: Error?
	private var header: FileHeader!
	private var chunkNumber: UInt64 = 0
	private var cleartextChunk: [UInt8] = []

	init(cryptor: Cryptor, wrapped: InputStream) {
		self.cryptor = cryptor
		self.wrapped = wrapped
		super.init()
	}

	override var streamStatus: Stream.Status {
		return error != nil ? .error : wrapped.streamStatus
	}

	override var streamError: Error? {
		return error ?? wrapped.streamError
	}

	override var hasBytesAvailable: Bool {
		return error != nil ? false : wrapped.hasBytesAvailable
	}

	override func schedule(in aRunLoop: RunLoop, forMode mode: RunLoop.Mode) {
		wrapped.schedule(in: aRunLoop, forMode: mode)
	}

	override func open() {
		wrapped.open()
	}

	override func close() {
		wrapped.close()
	}

	override func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
		if error != nil {
			return -1
		}

		do {
			if cleartextChunk.isEmpty {
				try decrypt()
			}

			let taken = min(len, cleartextChunk.count)
			for i in 0 ..< taken {
				buffer[i] = cleartextChunk[i]
			}

			cleartextChunk = Array(cleartextChunk.suffix(from: taken))

			return taken

		} catch {
			self.error = error
			return -1
		}
	}

	private func decrypt() throws {
		precondition(cleartextChunk.isEmpty)

		if header == nil {
			let ciphertextHeader = try wrapped.readFullyIntoArray(maxLength: cryptor.fileHeaderSize)
			guard ciphertextHeader.count == cryptor.fileHeaderSize else {
				throw CryptoError.ioError
			}

			header = try cryptor.decryptHeader(ciphertextHeader)
		}

		let ciphertextChunk = try wrapped.readFullyIntoArray(maxLength: cryptor.ciphertextChunkSize)
		guard !ciphertextChunk.isEmpty else {
			return
		}

		cleartextChunk = try cryptor.decryptSingleChunk(ciphertextChunk, chunkNumber: chunkNumber, headerNonce: header.nonce, fileKey: header.contentKey)
		chunkNumber += 1
	}
}

final class CryptorEncryptOutputStream: OutputStream {
	private let cryptor: Cryptor
	private let wrapped: OutputStream
	private var error: Error?
	private var header: FileHeader!
	private var chunkNumber: UInt64 = 0
	private var cleartextChunk: [UInt8] = []

	init(cryptor: Cryptor, wrapped: OutputStream) {
		self.cryptor = cryptor
		self.wrapped = wrapped
		super.init()
	}

	override var streamStatus: Stream.Status {
		return error != nil ? .error : wrapped.streamStatus
	}

	override var streamError: Error? {
		return error ?? wrapped.streamError
	}

	override func schedule(in aRunLoop: RunLoop, forMode mode: RunLoop.Mode) {
		wrapped.schedule(in: aRunLoop, forMode: mode)
	}

	override func open() {
		wrapped.open()
	}

	override func close() {
		try? encrypt()
		wrapped.close()
	}

	override func write(_ buffer: UnsafePointer<UInt8>, maxLength len: Int) -> Int {
		if error != nil {
			return -1
		}

		do {
			if cleartextChunk.count == cryptor.cleartextChunkSize {
				try encrypt()
			}

			let taken = min(len, cryptor.cleartextChunkSize - cleartextChunk.count)
			cleartextChunk.append(contentsOf: UnsafeBufferPointer(start: buffer, count: taken))

			return taken

		} catch {
			self.error = error
			return -1
		}
	}

	private func encrypt() throws {
		if header == nil {
			header = try cryptor.createHeader()
			let ciphertextHeader = try cryptor.encryptHeader(header)
			let result = wrapped.writeFully(ciphertextHeader, maxLength: ciphertextHeader.count)
			if result != ciphertextHeader.count {
				throw CryptoError.ioError
			}
		}

		let ciphertextChunk = try cryptor.encryptSingleChunk(cleartextChunk, chunkNumber: chunkNumber, headerNonce: header.nonce, fileKey: header.contentKey)
		cleartextChunk = []
		chunkNumber += 1

		let result = wrapped.writeFully(ciphertextChunk, maxLength: ciphertextChunk.count)
		if result != ciphertextChunk.count {
			throw CryptoError.ioError
		}
	}
}

private extension InputStream {
	func readFully(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
		var offset = 0
		while offset < len {
			let result = read(buffer + offset, maxLength: len - offset)
			if result < 0 {
				return result
			}
			if result == 0 {
				return offset
			}
			offset += result
		}
		return len
	}

	func readFullyIntoArray(maxLength len: Int) throws -> [UInt8] {
		var buffer = [UInt8](repeating: 0, count: len)
		let result = readFully(&buffer, maxLength: len)
		if result < 0 {
			throw streamError!
		}
		return Array(buffer.prefix(result))
	}
}

private extension OutputStream {
	func writeFully(_ buffer: UnsafePointer<UInt8>, maxLength len: Int) -> Int {
		var offset = 0
		while offset < len {
			let result = write(buffer + offset, maxLength: len - offset)
			if result < 0 {
				return result
			}
			if result == 0 {
				return -1
			}
			offset += result
		}
		return len
	}

	func writeFullyFromArray(_ array: [UInt8]) throws {
		let result = writeFully(array, maxLength: array.count)
		if result != array.count {
			throw streamError!
		}
	}
}
