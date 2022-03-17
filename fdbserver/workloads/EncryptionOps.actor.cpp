/*
 * EncryptionOps.actor.cpp
 *
 * This source file is part of the FoundationDB open source project
 *
 * Copyright 2013-2018 Apple Inc. and the FoundationDB project authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "fdbclient/DatabaseContext.h"
#include "fdbclient/NativeAPI.actor.h"
#include "flow/IRandom.h"
#include "flow/BlobCipher.h"
#include "fdbserver/workloads/workloads.actor.h"
#include "flow/Trace.h"
#include "flow/actorcompiler.h" // This must be the last #include.

//#if ENCRYPTION_ENABLED

#include <chrono>
#include <cstring>
#include <memory>
#include <random>

#define MEGA_BYTES (1024 * 1024)
#define NANO_SECOND (1000 * 1000 * 1000)

struct WorkloadMetrics {
	double totalEncryptTimeNS;
	double totalDecryptTimeNS;
	double totalKeyDerivationTimeNS;
	int64_t totalBytes;

	void reset() {
		totalEncryptTimeNS = 0;
		totalDecryptTimeNS = 0;
		totalKeyDerivationTimeNS = 0;
		totalBytes = 0;
	}

	WorkloadMetrics() { reset(); }

	double computeEncryptThroughputMBPS() {
		// convert bytes -> MBs & nano-seonds -> seconds
		return (totalBytes * NANO_SECOND) / (totalEncryptTimeNS * MEGA_BYTES);
	}

	double computeDecryptThroughputMBPS() {
		// convert bytes -> MBs & nano-seonds -> seconds
		return (totalBytes * NANO_SECOND) / (totalDecryptTimeNS * MEGA_BYTES);
	}

	void updateKeyDerivationTime(double val) { totalKeyDerivationTimeNS += val; }
	void updateEncryptionTime(double val) { totalEncryptTimeNS += val; }
	void updateDecryptionTime(double val) { totalDecryptTimeNS += val; }
	void updateBytes(int64_t val) { totalBytes += val; }

	void recordMetrics(const std::string& mode, const int numIterations) {
		TraceEvent("EncryptionOpsWorkload")
		    .detail("Mode", mode)
		    .detail("EncryptTimeMS", totalEncryptTimeNS / 1000)
		    .detail("DecryptTimeMS", totalDecryptTimeNS / 1000)
		    .detail("EncryptMBPS", computeEncryptThroughputMBPS())
		    .detail("DecryptMBPS", computeDecryptThroughputMBPS())
		    .detail("KeyDerivationTimeMS", totalKeyDerivationTimeNS / 1000)
		    .detail("TotalBytes", totalBytes)
		    .detail("AvgCommitSize", totalBytes / numIterations);
	}
};

struct EncryptionOpsWorkload : TestWorkload {
	int mode;
	int64_t numIterations;
	int pageSize;
	int maxBufSize;
	std::unique_ptr<uint8_t[]> buff;
	std::unique_ptr<uint8_t[]> validationBuff;

	BlobCipherIV iv;
	std::unique_ptr<uint8_t[]> parentCipher;
	Arena arena;
	std::unique_ptr<WorkloadMetrics> metrics;

	BlobCipherDomainId minDomainId;
	BlobCipherDomainId maxDomainId;
	BlobCipherBaseKeyId minBaseCipherId;

	EncryptionOpsWorkload(WorkloadContext const& wcx) : TestWorkload(wcx) {
		mode = getOption(options, LiteralStringRef("fixedSize"), 1);
		numIterations = getOption(options, LiteralStringRef("numIterations"), 10);
		pageSize = getOption(options, LiteralStringRef("pageSize"), 4096);
		maxBufSize = getOption(options, LiteralStringRef("maxBufSize"), 512 * 1024);
		buff = std::make_unique<uint8_t[]>(maxBufSize);
		validationBuff = std::make_unique<uint8_t[]>(maxBufSize);

		iv = getRandomIV();
		parentCipher = std::make_unique<uint8_t[]>(AES_256_KEY_LENGTH);
		generateRandomData(parentCipher.get(), AES_256_KEY_LENGTH);

		minDomainId = wcx.clientId * 100 + mode * 30 + 1;
		maxDomainId = deterministicRandom()->randomInt(minDomainId, minDomainId + 10) + 5;
		minBaseCipherId = 100;

		metrics = std::make_unique<WorkloadMetrics>();

		TraceEvent("EncryptionOpsWorkload").detail("Mode", getModeStr()).detail("ClientId", wcx.clientId);
	}

	~EncryptionOpsWorkload() { TraceEvent("EncryptionOpsWorkload_Done").log(); }

	bool isFixedSizePayload() { return mode == 1; }

	BlobCipherIV getRandomIV() {
		generateRandomData(iv.data(), iv.size());
		return iv;
	}

	std::string getModeStr() const {
		if (mode == 1) {
			return "FixedSize";
		} else if (mode == 0) {
			return "VariableSize";
		}
		// no other mode supported
		throw internal_error();
	}

	StringRef doEncryption(Reference<BlobCipherKey> key, uint8_t* payload, int len, BlobCipherEncryptHeader* header) {
		EncryptBlobCipherAes265Ctr encryptor(key, iv);

		auto start = std::chrono::high_resolution_clock::now();
		auto encrypted = encryptor.encrypt(buff.get(), len, header, arena);
		auto end = std::chrono::high_resolution_clock::now();

		// validate encrypted buffer size and contents (not matching with plaintext)
		ASSERT(encrypted.size() == len);
		std::copy(encrypted.begin(), encrypted.end(), validationBuff.get());
		ASSERT(memcmp(validationBuff.get(), buff.get(), len) != 0);
		ASSERT(header->flags.headerVersion == EncryptBlobCipherAes265Ctr::ENCRYPT_HEADER_VERSION);

		metrics->updateEncryptionTime(std::chrono::duration<double, std::nano>(end - start).count());
		return encrypted;
	}

	void generateRandomBaseCipher(const int maxLen, uint8_t* buff, int* retLen) {
		memset(buff, 0, maxLen);
		*retLen = deterministicRandom()->randomInt(maxLen / 2, maxLen);
		generateRandomData(buff, *retLen);
	}

	void setupCipherEssentials() {
		auto& cipherKeyCache = BlobCipherKeyCache::getInstance();

		TraceEvent("SetupCipherEssentials_Start").detail("MinDomainId", minDomainId).detail("MaxDomainId", maxDomainId);

		uint8_t buff[AES_256_KEY_LENGTH];
		std::vector<Reference<BlobCipherKey>> cipherKeys;
		for (BlobCipherDomainId id = minDomainId; id <= maxDomainId; id++) {
			int cipherLen = 0;
			generateRandomBaseCipher(AES_256_KEY_LENGTH, &buff[0], &cipherLen);
			cipherKeyCache.insertCipherKey(id, minBaseCipherId, buff, cipherLen);

			ASSERT(cipherLen > 0 && cipherLen <= AES_256_KEY_LENGTH);

			cipherKeys = cipherKeyCache.getAllCiphers(id);
			ASSERT(cipherKeys.size() == 1);
		}

		TraceEvent("SetupCipherEssentials_Done").detail("MinDomainId", minDomainId).detail("MaxDomainId", maxDomainId);
	}

	void resetCipherEssentials() {
		auto& cipherKeyCache = BlobCipherKeyCache::getInstance();
		cipherKeyCache.cleanup();

		TraceEvent("ResetCipherEssentials_Done").log();
	}

	void updateLatestBaseCipher(const BlobCipherDomainId encryptDomainId,
	                            uint8_t* baseCipher,
	                            int* baseCipherLen,
	                            BlobCipherBaseKeyId* nextBaseCipherId) {
		auto& cipherKeyCache = BlobCipherKeyCache::getInstance();
		Reference<BlobCipherKey> cipherKey = cipherKeyCache.getLatestCipherKey(encryptDomainId);
		*nextBaseCipherId = cipherKey->getBaseCipherId() + 1;

		generateRandomBaseCipher(AES_256_KEY_LENGTH, baseCipher, baseCipherLen);

		ASSERT(*baseCipherLen > 0 && *baseCipherLen <= AES_256_KEY_LENGTH);
		TraceEvent("UpdateBaseCipher").detail("DomainId", encryptDomainId).detail("BaseCipherId", *nextBaseCipherId);
	}

	void doDecryption(StringRef encrypted,
	                  int len,
	                  const BlobCipherEncryptHeader& header,
	                  uint8_t* originalPayload,
	                  uint8_t* validationBuff,
	                  Reference<BlobCipherKey> orgCipherKey) {
		ASSERT(header.flags.headerVersion == EncryptBlobCipherAes265Ctr::ENCRYPT_HEADER_VERSION);
		ASSERT(header.flags.encryptMode == BLOB_CIPHER_ENCRYPT_MODE_AES_256_CTR);

		auto& cipherKeyCache = BlobCipherKeyCache::getInstance();
		Reference<BlobCipherKey> cipherKey = cipherKeyCache.getCipherKey(header.encryptDomainId, header.baseCipherId);
		ASSERT(cipherKey.isValid());
		ASSERT(cipherKey->isEqual(orgCipherKey));

		DecryptBlobCipherAes256Ctr decryptor(cipherKey, iv);

		auto start = std::chrono::high_resolution_clock::now();
		Standalone<StringRef> decrypted = decryptor.decrypt(encrypted.begin(), len, header, arena);
		auto end = std::chrono::high_resolution_clock::now();

		// validate decrypted buffer size and contents (matching with original plaintext)
		ASSERT(decrypted.size() == len);
		std::copy(decrypted.begin(), decrypted.end(), validationBuff);
		ASSERT(memcmp(validationBuff, originalPayload, len) == 0);

		metrics->updateDecryptionTime(std::chrono::duration<double, std::nano>(end - start).count());
	}

	Future<Void> setup(Database const& ctx) override { return Void(); }

	std::string description() const override { return "EncryptionOps"; }

	Future<Void> start(Database const& cx) override {
		try {
			uint8_t baseCipher[AES_256_KEY_LENGTH];
			int baseCipherLen = 0;
			BlobCipherBaseKeyId nextBaseCipherId;

			// Setup encryptDomainIds and corresponding baseCipher details
			setupCipherEssentials();

			for (int i = 0; i < numIterations; i++) {
				bool updateBaseCipher = deterministicRandom()->randomInt(1, 100) < 5;

				// Step-1: Encryption key derivation, caching the cipher for later use
				auto& cipherKeyCache = BlobCipherKeyCache::getInstance();

				// randomly select a domainId
				const BlobCipherDomainId encryptDomainId = deterministicRandom()->randomInt(minDomainId, maxDomainId);
				ASSERT(encryptDomainId >= minDomainId && encryptDomainId <= maxDomainId);

				if (updateBaseCipher) {
					// simulate baseCipherId getting refreshed/updated
					updateLatestBaseCipher(encryptDomainId, &baseCipher[0], &baseCipherLen, &nextBaseCipherId);
					cipherKeyCache.insertCipherKey(encryptDomainId, nextBaseCipherId, &baseCipher[0], baseCipherLen);
				}

				auto start = std::chrono::high_resolution_clock::now();
				Reference<BlobCipherKey> cipherKey = cipherKeyCache.getLatestCipherKey(encryptDomainId);
				auto end = std::chrono::high_resolution_clock::now();
				metrics->updateKeyDerivationTime(std::chrono::duration<double, std::nano>(end - start).count());

				// Validate sanity of "getLatestCipher", especially when baseCipher gets updated
				if (updateBaseCipher) {
					ASSERT(cipherKey->getBaseCipherId() == nextBaseCipherId);
					ASSERT(cipherKey->getBaseCipherLen() == baseCipherLen);
					ASSERT(memcmp(cipherKey->rawBaseCipher(), baseCipher, baseCipherLen) == 0);
				}

				int dataLen = isFixedSizePayload() ? pageSize : deterministicRandom()->randomInt(100, maxBufSize);
				generateRandomData(buff.get(), dataLen);

				// Encrypt the payload - generates BlobCipherEncryptHeader to assist decryption later
				BlobCipherEncryptHeader header;
				try {
					auto encrypted = doEncryption(cipherKey, buff.get(), dataLen, &header);

					// Decrypt the payload - parses the BlobCipherEncryptHeader, fetch corresponding cipherKey and
					// decrypt
					doDecryption(encrypted, dataLen, header, buff.get(), validationBuff.get(), cipherKey);
				} catch (Error& e) {
					TraceEvent("Failed")
					    .detail("DomainId", encryptDomainId)
					    .detail("BaseCipherId", cipherKey->getBaseCipherId());
					throw;
				}

				metrics->updateBytes(dataLen);
			}

			// Cleanup cipherKeys
			resetCipherEssentials();
		} catch (Error& e) {
			TraceEvent("Failed");
			throw;
		}

		return Void();
	}

	Future<bool> check(Database const& cx) override { return true; }

	void getMetrics(std::vector<PerfMetric>& m) override { metrics->recordMetrics(getModeStr(), numIterations); }
};

WorkloadFactory<EncryptionOpsWorkload> EncryptionOpsWorkloadFactory("EncryptionOps");

//#endif // ENCRYPTION_ENABLED
