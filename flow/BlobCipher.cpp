/*
 * BlobCipher.cpp
 *
 * This source file is part of the FoundationDB open source project
 *
 * Copyright 2013-2022 Apple Inc. and the FoundationDB project authors
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

#include "flow/BlobCipher.h"

#include "flow/Arena.h"
#include "flow/EncryptUtils.h"
#include "flow/Knobs.h"
#include "flow/Error.h"
#include "flow/FastRef.h"
#include "flow/IRandom.h"
#include "flow/ITrace.h"
#include "flow/network.h"
#include "flow/Trace.h"
#include "flow/UnitTest.h"

#include <cstring>
#include <memory>
#include <string>
#include <utility>

namespace {
bool isEncryptHeaderAuthTokenModeValid(const EncryptAuthTokenMode mode) {
	return mode >= ENCRYPT_HEADER_AUTH_TOKEN_MODE_NONE && mode < ENCRYPT_HEADER_AUTH_TOKEN_LAST;
}
} // namespace

// BlobCipherKey class methods

BlobCipherKey::BlobCipherKey(const EncryptCipherDomainId& domainId,
                             const EncryptCipherBaseKeyId& baseCiphId,
                             const uint8_t* baseCiph,
                             int baseCiphLen) {
	EncryptCipherRandomSalt salt;
	if (g_network->isSimulated()) {
		salt = deterministicRandom()->randomUInt64();
	} else {
		salt = nondeterministicRandom()->randomUInt64();
	}
	initKey(domainId, baseCiph, baseCiphLen, baseCiphId, salt);
}

BlobCipherKey::BlobCipherKey(const EncryptCipherDomainId& domainId,
                             const EncryptCipherBaseKeyId& baseCiphId,
                             const uint8_t* baseCiph,
                             int baseCiphLen,
                             const EncryptCipherRandomSalt& salt) {
	initKey(domainId, baseCiph, baseCiphLen, baseCiphId, salt);
}

void BlobCipherKey::initKey(const EncryptCipherDomainId& domainId,
                            const uint8_t* baseCiph,
                            int baseCiphLen,
                            const EncryptCipherBaseKeyId& baseCiphId,
                            const EncryptCipherRandomSalt& salt) {
	// Set the base encryption key properties
	baseCipher = std::make_unique<uint8_t[]>(AES_256_KEY_LENGTH);
	memset(baseCipher.get(), 0, AES_256_KEY_LENGTH);
	memcpy(baseCipher.get(), baseCiph, std::min<int>(baseCiphLen, AES_256_KEY_LENGTH));
	baseCipherLen = baseCiphLen;
	baseCipherId = baseCiphId;
	// Set the encryption domain for the base encryption key
	encryptDomainId = domainId;
	randomSalt = salt;
	// derive the encryption key
	cipher = std::make_unique<uint8_t[]>(AES_256_KEY_LENGTH);
	memset(cipher.get(), 0, AES_256_KEY_LENGTH);
	applyHmacSha256Derivation();
	// update the key creation time
	creationTime = now();

	TraceEvent("BlobCipherKey")
	    .detail("DomainId", domainId)
	    .detail("BaseCipherId", baseCipherId)
	    .detail("BaseCipherLen", baseCipherLen)
	    .detail("RandomSalt", randomSalt)
	    .detail("CreationTime", creationTime);
}

void BlobCipherKey::applyHmacSha256Derivation() {
	Arena arena;
	uint8_t buf[baseCipherLen + sizeof(EncryptCipherRandomSalt)];
	memcpy(&buf[0], baseCipher.get(), baseCipherLen);
	memcpy(&buf[0] + baseCipherLen, &randomSalt, sizeof(EncryptCipherRandomSalt));
	HmacSha256DigestGen hmacGen(baseCipher.get(), baseCipherLen);
	StringRef digest = hmacGen.digest(&buf[0], baseCipherLen + sizeof(EncryptCipherRandomSalt), arena);
	std::copy(digest.begin(), digest.end(), cipher.get());
	if (digest.size() < AES_256_KEY_LENGTH) {
		memcpy(cipher.get() + digest.size(), buf, AES_256_KEY_LENGTH - digest.size());
	}
}

void BlobCipherKey::reset() {
	memset(baseCipher.get(), 0, baseCipherLen);
	memset(cipher.get(), 0, AES_256_KEY_LENGTH);
}

// BlobKeyIdCache class methods

BlobCipherKeyIdCache::BlobCipherKeyIdCache()
  : domainId(ENCRYPT_INVALID_DOMAIN_ID), latestBaseCipherKeyId(), latestRandomSalt() {}

BlobCipherKeyIdCache::BlobCipherKeyIdCache(EncryptCipherDomainId dId)
  : domainId(dId), latestBaseCipherKeyId(), latestRandomSalt() {
	TraceEvent("Init_BlobCipherKeyIdCache").detail("DomainId", domainId);
}

BlobCipherKeyIdCacheKey BlobCipherKeyIdCache::getCacheKey(const EncryptCipherBaseKeyId& baseCipherKeyId,
                                                          const EncryptCipherRandomSalt& salt) {
	if (baseCipherKeyId == ENCRYPT_INVALID_CIPHER_KEY_ID || salt == ENCRYPT_INVALID_RANDOM_SALT) {
		throw encrypt_invalid_id();
	}
	return std::make_pair(baseCipherKeyId, salt);
}

Reference<BlobCipherKey> BlobCipherKeyIdCache::getLatestCipherKey() {
	if (!latestBaseCipherKeyId.present()) {
		return Reference<BlobCipherKey>();
	}
	ASSERT_NE(latestBaseCipherKeyId.get(), ENCRYPT_INVALID_CIPHER_KEY_ID);
	ASSERT(latestRandomSalt.present());
	ASSERT_NE(latestRandomSalt.get(), ENCRYPT_INVALID_RANDOM_SALT);

	return getCipherByBaseCipherId(latestBaseCipherKeyId.get(), latestRandomSalt.get());
}

Reference<BlobCipherKey> BlobCipherKeyIdCache::getCipherByBaseCipherId(const EncryptCipherBaseKeyId& baseCipherKeyId,
                                                                       const EncryptCipherRandomSalt& salt) {
	BlobCipherKeyIdCacheMapCItr itr = keyIdCache.find(getCacheKey(baseCipherKeyId, salt));
	if (itr == keyIdCache.end()) {
		return Reference<BlobCipherKey>();
	}
	return itr->second;
}

Reference<BlobCipherKey> BlobCipherKeyIdCache::insertBaseCipherKey(const EncryptCipherBaseKeyId& baseCipherId,
                                                                   const uint8_t* baseCipher,
                                                                   int baseCipherLen) {
	ASSERT_GT(baseCipherId, ENCRYPT_INVALID_CIPHER_KEY_ID);

	// BaseCipherKeys are immutable, given the routine invocation updates 'latestCipher',
	// ensure no key-tampering is done
	Reference<BlobCipherKey> latestCipherKey = getLatestCipherKey();
	if (latestCipherKey.isValid() && latestCipherKey->getBaseCipherId() == baseCipherId) {
		if (memcmp(latestCipherKey->rawBaseCipher(), baseCipher, baseCipherLen) == 0) {
			TraceEvent("InsertBaseCipherKey_AlreadyPresent")
			    .detail("BaseCipherKeyId", baseCipherId)
			    .detail("DomainId", domainId);
			// Key is already present; nothing more to do.
			return latestCipherKey;
		} else {
			TraceEvent("InsertBaseCipherKey_UpdateCipher")
			    .detail("BaseCipherKeyId", baseCipherId)
			    .detail("DomainId", domainId);
			throw encrypt_update_cipher();
		}
	}

	Reference<BlobCipherKey> cipherKey =
	    makeReference<BlobCipherKey>(domainId, baseCipherId, baseCipher, baseCipherLen);
	BlobCipherKeyIdCacheKey cacheKey = getCacheKey(cipherKey->getBaseCipherId(), cipherKey->getSalt());
	keyIdCache.emplace(cacheKey, cipherKey);

	// Update the latest BaseCipherKeyId for the given encryption domain
	latestBaseCipherKeyId = baseCipherId;
	latestRandomSalt = cipherKey->getSalt();

	return cipherKey;
}

Reference<BlobCipherKey> BlobCipherKeyIdCache::insertBaseCipherKey(const EncryptCipherBaseKeyId& baseCipherId,
                                                                   const uint8_t* baseCipher,
                                                                   int baseCipherLen,
                                                                   const EncryptCipherRandomSalt& salt) {
	ASSERT_NE(baseCipherId, ENCRYPT_INVALID_CIPHER_KEY_ID);
	ASSERT_NE(salt, ENCRYPT_INVALID_RANDOM_SALT);

	BlobCipherKeyIdCacheKey cacheKey = getCacheKey(baseCipherId, salt);

	// BaseCipherKeys are immutable, ensure that cached value doesn't get updated.
	BlobCipherKeyIdCacheMapCItr itr = keyIdCache.find(cacheKey);
	if (itr != keyIdCache.end()) {
		if (memcmp(itr->second->rawBaseCipher(), baseCipher, baseCipherLen) == 0) {
			TraceEvent("InsertBaseCipherKey_AlreadyPresent")
			    .detail("BaseCipherKeyId", baseCipherId)
			    .detail("DomainId", domainId);
			// Key is already present; nothing more to do.
			return itr->second;
		} else {
			TraceEvent("InsertBaseCipherKey_UpdateCipher")
			    .detail("BaseCipherKeyId", baseCipherId)
			    .detail("DomainId", domainId);
			throw encrypt_update_cipher();
		}
	}

	Reference<BlobCipherKey> cipherKey =
	    makeReference<BlobCipherKey>(domainId, baseCipherId, baseCipher, baseCipherLen, salt);
	keyIdCache.emplace(cacheKey, cipherKey);
	return cipherKey;
}

void BlobCipherKeyIdCache::cleanup() {
	for (auto& keyItr : keyIdCache) {
		keyItr.second->reset();
	}

	keyIdCache.clear();
}

std::vector<Reference<BlobCipherKey>> BlobCipherKeyIdCache::getAllCipherKeys() {
	std::vector<Reference<BlobCipherKey>> cipherKeys;
	for (auto& keyItr : keyIdCache) {
		cipherKeys.push_back(keyItr.second);
	}
	return cipherKeys;
}

// BlobCipherKeyCache class methods

Reference<BlobCipherKey> BlobCipherKeyCache::insertCipherKey(const EncryptCipherDomainId& domainId,
                                                             const EncryptCipherBaseKeyId& baseCipherId,
                                                             const uint8_t* baseCipher,
                                                             int baseCipherLen) {
	if (domainId == ENCRYPT_INVALID_DOMAIN_ID || baseCipherId == ENCRYPT_INVALID_CIPHER_KEY_ID) {
		throw encrypt_invalid_id();
	}

	try {
		auto domainItr = domainCacheMap.find(domainId);
		if (domainItr == domainCacheMap.end()) {
			// Add mapping to track new encryption domain
			Reference<BlobCipherKeyIdCache> keyIdCache = makeReference<BlobCipherKeyIdCache>(domainId);
			Reference<BlobCipherKey> cipherKey =
			    keyIdCache->insertBaseCipherKey(baseCipherId, baseCipher, baseCipherLen);
			domainCacheMap.emplace(domainId, keyIdCache);
			return cipherKey;
		} else {
			// Track new baseCipher keys
			Reference<BlobCipherKeyIdCache> keyIdCache = domainItr->second;
			return keyIdCache->insertBaseCipherKey(baseCipherId, baseCipher, baseCipherLen);
		}

		TraceEvent("InsertCipherKey").detail("DomainId", domainId).detail("BaseCipherKeyId", baseCipherId);
	} catch (Error& e) {
		TraceEvent("InsertCipherKey_Failed").detail("BaseCipherKeyId", baseCipherId).detail("DomainId", domainId);
		throw;
	}
}

Reference<BlobCipherKey> BlobCipherKeyCache::insertCipherKey(const EncryptCipherDomainId& domainId,
                                                             const EncryptCipherBaseKeyId& baseCipherId,
                                                             const uint8_t* baseCipher,
                                                             int baseCipherLen,
                                                             const EncryptCipherRandomSalt& salt) {
	if (domainId == ENCRYPT_INVALID_DOMAIN_ID || baseCipherId == ENCRYPT_INVALID_CIPHER_KEY_ID ||
	    salt == ENCRYPT_INVALID_RANDOM_SALT) {
		throw encrypt_invalid_id();
	}

	Reference<BlobCipherKey> cipherKey;
	try {
		auto domainItr = domainCacheMap.find(domainId);
		if (domainItr == domainCacheMap.end()) {
			// Add mapping to track new encryption domain
			Reference<BlobCipherKeyIdCache> keyIdCache = makeReference<BlobCipherKeyIdCache>(domainId);
			cipherKey = keyIdCache->insertBaseCipherKey(baseCipherId, baseCipher, baseCipherLen, salt);
			domainCacheMap.emplace(domainId, keyIdCache);
		} else {
			// Track new baseCipher keys
			Reference<BlobCipherKeyIdCache> keyIdCache = domainItr->second;
			cipherKey = keyIdCache->insertBaseCipherKey(baseCipherId, baseCipher, baseCipherLen, salt);
		}

		TraceEvent("InsertCipherKey")
		    .detail("DomainId", domainId)
		    .detail("BaseCipherKeyId", baseCipherId)
		    .detail("Salt", salt);
	} catch (Error& e) {
		TraceEvent("InsertCipherKey_Failed")
		    .detail("BaseCipherKeyId", baseCipherId)
		    .detail("DomainId", domainId)
		    .detail("Salt", salt);
		throw;
	}

	return cipherKey;
}

Reference<BlobCipherKey> BlobCipherKeyCache::getLatestCipherKey(const EncryptCipherDomainId& domainId) {
	if (domainId == ENCRYPT_INVALID_DOMAIN_ID) {
		TraceEvent("GetLatestCipherKey_InvalidID").detail("DomainId", domainId);
		throw encrypt_invalid_id();
	}
	auto domainItr = domainCacheMap.find(domainId);
	if (domainItr == domainCacheMap.end()) {
		TraceEvent("GetLatestCipherKey_DomainNotFound").detail("DomainId", domainId);
		return Reference<BlobCipherKey>();
	}

	Reference<BlobCipherKeyIdCache> keyIdCache = domainItr->second;
	Reference<BlobCipherKey> cipherKey = keyIdCache->getLatestCipherKey();
	if (cipherKey.isValid() && (now() - cipherKey->getCreationTime()) > FLOW_KNOBS->ENCRYPT_CIPHER_KEY_CACHE_TTL) {
		TraceEvent("GetLatestCipherKey_ExpiredTTL")
		    .detail("DomainId", domainId)
		    .detail("BaseCipherId", cipherKey->getBaseCipherId());
		return Reference<BlobCipherKey>();
	}

	return cipherKey;
}

Reference<BlobCipherKey> BlobCipherKeyCache::getCipherKey(const EncryptCipherDomainId& domainId,
                                                          const EncryptCipherBaseKeyId& baseCipherId,
                                                          const EncryptCipherRandomSalt& salt) {
	auto domainItr = domainCacheMap.find(domainId);
	if (domainItr == domainCacheMap.end()) {
		return Reference<BlobCipherKey>();
	}

	Reference<BlobCipherKeyIdCache> keyIdCache = domainItr->second;
	return keyIdCache->getCipherByBaseCipherId(baseCipherId, salt);
}

void BlobCipherKeyCache::resetEncryptDomainId(const EncryptCipherDomainId domainId) {
	auto domainItr = domainCacheMap.find(domainId);
	if (domainItr == domainCacheMap.end()) {
		return;
	}

	Reference<BlobCipherKeyIdCache> keyIdCache = domainItr->second;
	keyIdCache->cleanup();
	TraceEvent("ResetEncryptDomainId").detail("DomainId", domainId);
}

void BlobCipherKeyCache::cleanup() noexcept {
	Reference<BlobCipherKeyCache> instance = BlobCipherKeyCache::getInstance();
	for (auto& domainItr : instance->domainCacheMap) {
		Reference<BlobCipherKeyIdCache> keyIdCache = domainItr.second;
		keyIdCache->cleanup();
		TraceEvent("BlobCipherKeyCache_Cleanup").detail("DomainId", domainItr.first);
	}

	instance->domainCacheMap.clear();
}

std::vector<Reference<BlobCipherKey>> BlobCipherKeyCache::getAllCiphers(const EncryptCipherDomainId& domainId) {
	auto domainItr = domainCacheMap.find(domainId);
	if (domainItr == domainCacheMap.end()) {
		return {};
	}

	Reference<BlobCipherKeyIdCache> keyIdCache = domainItr->second;
	return keyIdCache->getAllCipherKeys();
}

// EncryptBlobCipherAes265Ctr class methods

EncryptBlobCipherAes265Ctr::EncryptBlobCipherAes265Ctr(Reference<BlobCipherKey> tCipherKey,
                                                       Reference<BlobCipherKey> hCipherKey,
                                                       const uint8_t* cipherIV,
                                                       const int ivLen,
                                                       const EncryptAuthTokenMode mode)
  : ctx(EVP_CIPHER_CTX_new()), textCipherKey(tCipherKey), headerCipherKey(hCipherKey), authTokenMode(mode) {
	ASSERT(isEncryptHeaderAuthTokenModeValid(mode));
	ASSERT_EQ(ivLen, AES_256_IV_LENGTH);
	memcpy(&iv[0], cipherIV, ivLen);
	init();
}

EncryptBlobCipherAes265Ctr::EncryptBlobCipherAes265Ctr(Reference<BlobCipherKey> tCipherKey,
                                                       Reference<BlobCipherKey> hCipherKey,
                                                       const EncryptAuthTokenMode mode)
  : ctx(EVP_CIPHER_CTX_new()), textCipherKey(tCipherKey), headerCipherKey(hCipherKey), authTokenMode(mode) {
	ASSERT(isEncryptHeaderAuthTokenModeValid(mode));
	generateRandomData(iv, AES_256_IV_LENGTH);
	init();
}

void EncryptBlobCipherAes265Ctr::init() {
	if (ctx == nullptr) {
		throw encrypt_ops_error();
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, nullptr, nullptr) != 1) {
		throw encrypt_ops_error();
	}
	if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, textCipherKey.getPtr()->data(), iv) != 1) {
		throw encrypt_ops_error();
	}
}

Reference<EncryptBuf> EncryptBlobCipherAes265Ctr::encrypt(const uint8_t* plaintext,
                                                          const int plaintextLen,
                                                          BlobCipherEncryptHeader* header,
                                                          Arena& arena) {
	TEST(true); // Encrypting data with BlobCipher

	memset(reinterpret_cast<uint8_t*>(header), 0, sizeof(BlobCipherEncryptHeader));

	// Alloc buffer computation accounts for 'header authentication' generation scheme. If single-auth-token needs
	// to be generated, allocate buffer sufficient to append header to the cipherText optimizing memcpy cost.

	const int allocSize = authTokenMode == ENCRYPT_HEADER_AUTH_TOKEN_MODE_SINGLE
	                          ? plaintextLen + AES_BLOCK_SIZE + sizeof(BlobCipherEncryptHeader)
	                          : plaintextLen + AES_BLOCK_SIZE;
	Reference<EncryptBuf> encryptBuf = makeReference<EncryptBuf>(allocSize, arena);
	uint8_t* ciphertext = encryptBuf->begin();
	int bytes{ 0 };
	if (EVP_EncryptUpdate(ctx, ciphertext, &bytes, plaintext, plaintextLen) != 1) {
		TraceEvent("Encrypt_UpdateFailed")
		    .detail("BaseCipherId", textCipherKey->getBaseCipherId())
		    .detail("EncryptDomainId", textCipherKey->getDomainId());
		throw encrypt_ops_error();
	}

	int finalBytes{ 0 };
	if (EVP_EncryptFinal_ex(ctx, ciphertext + bytes, &finalBytes) != 1) {
		TraceEvent("Encrypt_FinalFailed")
		    .detail("BaseCipherId", textCipherKey->getBaseCipherId())
		    .detail("EncryptDomainId", textCipherKey->getDomainId());
		throw encrypt_ops_error();
	}

	if ((bytes + finalBytes) != plaintextLen) {
		TraceEvent("Encrypt_UnexpectedCipherLen")
		    .detail("PlaintextLen", plaintextLen)
		    .detail("EncryptedBufLen", bytes + finalBytes);
		throw encrypt_ops_error();
	}

	// Populate encryption header flags details
	header->flags.size = sizeof(BlobCipherEncryptHeader);
	header->flags.headerVersion = EncryptBlobCipherAes265Ctr::ENCRYPT_HEADER_VERSION;
	header->flags.encryptMode = ENCRYPT_CIPHER_MODE_AES_256_CTR;
	header->flags.authTokenMode = authTokenMode;

	// Populate cipherText encryption-key details
	header->cipherTextDetails.baseCipherId = textCipherKey->getBaseCipherId();
	header->cipherTextDetails.encryptDomainId = textCipherKey->getDomainId();
	header->cipherTextDetails.salt = textCipherKey->getSalt();
	memcpy(&header->iv[0], &iv[0], AES_256_IV_LENGTH);

	if (authTokenMode == ENCRYPT_HEADER_AUTH_TOKEN_MODE_NONE) {
		// No header 'authToken' generation needed.
	} else {
		// Populate header encryption-key details
		header->cipherHeaderDetails.encryptDomainId = headerCipherKey->getDomainId();
		header->cipherHeaderDetails.baseCipherId = headerCipherKey->getBaseCipherId();
		header->cipherHeaderDetails.salt = headerCipherKey->getSalt();

		// Populate header authToken details
		if (header->flags.authTokenMode == ENCRYPT_HEADER_AUTH_TOKEN_MODE_SINGLE) {
			ASSERT_GE(allocSize, (bytes + finalBytes + sizeof(BlobCipherEncryptHeader)));
			ASSERT_GE(encryptBuf->getLogicalSize(), (bytes + finalBytes + sizeof(BlobCipherEncryptHeader)));

			memcpy(&ciphertext[bytes + finalBytes],
			       reinterpret_cast<const uint8_t*>(header),
			       sizeof(BlobCipherEncryptHeader));
			StringRef authToken = computeAuthToken(ciphertext,
			                                       bytes + finalBytes + sizeof(BlobCipherEncryptHeader),
			                                       headerCipherKey->rawCipher(),
			                                       AES_256_KEY_LENGTH,
			                                       arena);
			memcpy(&header->singleAuthToken.authToken[0], authToken.begin(), AUTH_TOKEN_SIZE);
		} else {
			ASSERT_EQ(header->flags.authTokenMode, ENCRYPT_HEADER_AUTH_TOKEN_MODE_MULTI);

			StringRef cipherTextAuthToken =
			    computeAuthToken(ciphertext,
			                     bytes + finalBytes,
			                     reinterpret_cast<const uint8_t*>(&header->cipherTextDetails.salt),
			                     sizeof(EncryptCipherRandomSalt),
			                     arena);
			memcpy(&header->multiAuthTokens.cipherTextAuthToken[0], cipherTextAuthToken.begin(), AUTH_TOKEN_SIZE);
			StringRef headerAuthToken = computeAuthToken(reinterpret_cast<const uint8_t*>(header),
			                                             sizeof(BlobCipherEncryptHeader),
			                                             headerCipherKey->rawCipher(),
			                                             AES_256_KEY_LENGTH,
			                                             arena);
			memcpy(&header->multiAuthTokens.headerAuthToken[0], headerAuthToken.begin(), AUTH_TOKEN_SIZE);
		}
	}

	encryptBuf->setLogicalSize(plaintextLen);
	return encryptBuf;
}

Standalone<StringRef> EncryptBlobCipherAes265Ctr::encryptBlobGranuleChunk(const uint8_t* plaintext,
                                                                          const int plaintextLen) {
	Standalone<StringRef> encrypted = makeString(plaintextLen);
	uint8_t* ciphertext = mutateString(encrypted);
	int bytes{ 0 };

	if (EVP_EncryptUpdate(ctx, ciphertext, &bytes, plaintext, plaintextLen) != 1) {
		TraceEvent("Encrypt_UpdateFailed")
		    .detail("BaseCipherId", textCipherKey->getBaseCipherId())
		    .detail("EncryptDomainId", textCipherKey->getDomainId());
		throw encrypt_ops_error();
	}
	int finalBytes{ 0 };
	if (EVP_EncryptFinal_ex(ctx, ciphertext + bytes, &finalBytes) != 1) {
		TraceEvent("Encrypt_FinalFailed")
		    .detail("BaseCipherId", textCipherKey->getBaseCipherId())
		    .detail("EncryptDomainId", textCipherKey->getDomainId());
		throw encrypt_ops_error();
	}
	if ((bytes + finalBytes) != plaintextLen) {
		TraceEvent("Encrypt_UnexpectedCipherLen")
		    .detail("PlaintextLen", plaintextLen)
		    .detail("EncryptedBufLen", bytes + finalBytes);
		throw encrypt_ops_error();
	}
	return encrypted;
}

Standalone<StringRef> EncryptBlobCipherAes265Ctr::generateBlobFileEncryptionHeader(const uint8_t* ciphertext,
                                                                                   const int ciphertextLen) {
	// Ensure 'MultiToken' authentication mode
	ASSERT(authTokenMode == ENCRYPT_HEADER_AUTH_TOKEN_MODE_SINGLE);

	Arena arena;
	BlobCipherEncryptHeader header;

	memset(reinterpret_cast<uint8_t*>(&header), 0, sizeof(BlobCipherEncryptHeader));

	// Populate encryption header flags details
	header.flags.size = sizeof(BlobCipherEncryptHeader);
	header.flags.headerVersion = EncryptBlobCipherAes265Ctr::ENCRYPT_HEADER_VERSION;
	header.flags.encryptMode = ENCRYPT_CIPHER_MODE_AES_256_CTR;
	header.flags.authTokenMode = authTokenMode;

	// Populate cipherText encryption-key details
	header.cipherTextDetails.baseCipherId = textCipherKey->getBaseCipherId();
	header.cipherTextDetails.encryptDomainId = textCipherKey->getDomainId();
	header.cipherTextDetails.salt = textCipherKey->getSalt();
	memcpy(&header.iv[0], &iv[0], AES_256_IV_LENGTH);

	// Populate header encryption-key details
	header.cipherHeaderDetails.encryptDomainId = headerCipherKey->getDomainId();
	header.cipherHeaderDetails.baseCipherId = headerCipherKey->getBaseCipherId();
	header.cipherHeaderDetails.salt = headerCipherKey->getSalt();

	return BlobCipherEncryptHeader::toStringRef(header);
}

EncryptBlobCipherAes265Ctr::~EncryptBlobCipherAes265Ctr() {
	if (ctx != nullptr) {
		EVP_CIPHER_CTX_free(ctx);
	}
}

// DecryptBlobCipherAes256Ctr class methods

DecryptBlobCipherAes256Ctr::DecryptBlobCipherAes256Ctr(Reference<BlobCipherKey> tCipherKey,
                                                       Reference<BlobCipherKey> hCipherKey,
                                                       const uint8_t* iv)
  : ctx(EVP_CIPHER_CTX_new()), textCipherKey(tCipherKey), headerCipherKey(hCipherKey),
    headerAuthTokenValidationDone(false), authTokensValidationDone(false) {
	if (ctx == nullptr) {
		throw encrypt_ops_error();
	}
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, nullptr, nullptr)) {
		throw encrypt_ops_error();
	}
	if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, tCipherKey.getPtr()->data(), iv)) {
		throw encrypt_ops_error();
	}
}

void DecryptBlobCipherAes256Ctr::verifyHeaderAuthToken(const BlobCipherEncryptHeader& header, Arena& arena) {
	if (header.flags.authTokenMode != ENCRYPT_HEADER_AUTH_TOKEN_MODE_MULTI) {
		// NoneAuthToken mode; no authToken is generated; nothing to do
		// SingleAuthToken mode; verification will happen as part of decryption.
		return;
	}

	ASSERT_EQ(header.flags.authTokenMode, ENCRYPT_HEADER_AUTH_TOKEN_MODE_MULTI);

	BlobCipherEncryptHeader headerCopy;
	memcpy(reinterpret_cast<uint8_t*>(&headerCopy),
	       reinterpret_cast<const uint8_t*>(&header),
	       sizeof(BlobCipherEncryptHeader));
	memset(reinterpret_cast<uint8_t*>(&headerCopy.multiAuthTokens.headerAuthToken), 0, AUTH_TOKEN_SIZE);
	StringRef computedHeaderAuthToken = computeAuthToken(reinterpret_cast<const uint8_t*>(&headerCopy),
	                                                     sizeof(BlobCipherEncryptHeader),
	                                                     headerCipherKey->rawCipher(),
	                                                     AES_256_KEY_LENGTH,
	                                                     arena);
	if (memcmp(&header.multiAuthTokens.headerAuthToken[0], computedHeaderAuthToken.begin(), AUTH_TOKEN_SIZE) != 0) {
		TraceEvent("VerifyEncryptBlobHeader_AuthTokenMismatch")
		    .detail("HeaderVersion", header.flags.headerVersion)
		    .detail("HeaderMode", header.flags.encryptMode)
		    .detail("MultiAuthHeaderAuthToken",
		            StringRef(arena, &header.multiAuthTokens.headerAuthToken[0], AUTH_TOKEN_SIZE).toString())
		    .detail("ComputedHeaderAuthToken", computedHeaderAuthToken.toString());
		throw encrypt_header_authtoken_mismatch();
	}

	headerAuthTokenValidationDone = true;
}

void DecryptBlobCipherAes256Ctr::verifyHeaderSingleAuthToken(const uint8_t* ciphertext,
                                                             const int ciphertextLen,
                                                             const BlobCipherEncryptHeader& header,
                                                             uint8_t* buff,
                                                             Arena& arena) {
	// Header authToken not set for single auth-token mode.
	ASSERT(!headerAuthTokenValidationDone);

	// prepare the payload {cipherText + encryptionHeader}
	memcpy(&buff[0], ciphertext, ciphertextLen);
	memcpy(&buff[ciphertextLen], reinterpret_cast<const uint8_t*>(&header), sizeof(BlobCipherEncryptHeader));
	// ensure the 'authToken' is reset before computing the 'authentication token'
	BlobCipherEncryptHeader* eHeader = (BlobCipherEncryptHeader*)(&buff[ciphertextLen]);
	memset(reinterpret_cast<uint8_t*>(&eHeader->singleAuthToken), 0, 2 * AUTH_TOKEN_SIZE);

	StringRef computed = computeAuthToken(
	    buff, ciphertextLen + sizeof(BlobCipherEncryptHeader), headerCipherKey->rawCipher(), AES_256_KEY_LENGTH, arena);
	if (memcmp(&header.singleAuthToken.authToken[0], computed.begin(), AUTH_TOKEN_SIZE) != 0) {
		TraceEvent("VerifyEncryptBlobHeader_AuthTokenMismatch")
		    .detail("HeaderVersion", header.flags.headerVersion)
		    .detail("HeaderMode", header.flags.encryptMode)
		    .detail("SingleAuthToken",
		            StringRef(arena, &header.singleAuthToken.authToken[0], AUTH_TOKEN_SIZE).toString())
		    .detail("ComputedSingleAuthToken", computed.toString());
		throw encrypt_header_authtoken_mismatch();
	}
}

void DecryptBlobCipherAes256Ctr::verifyHeaderMultiAuthToken(const uint8_t* ciphertext,
                                                            const int ciphertextLen,
                                                            const BlobCipherEncryptHeader& header,
                                                            uint8_t* buff,
                                                            Arena& arena) {
	if (!headerAuthTokenValidationDone) {
		verifyHeaderAuthToken(header, arena);
	}
	StringRef computedCipherTextAuthToken =
	    computeAuthToken(ciphertext,
	                     ciphertextLen,
	                     reinterpret_cast<const uint8_t*>(&header.cipherTextDetails.salt),
	                     sizeof(EncryptCipherRandomSalt),
	                     arena);
	if (memcmp(&header.multiAuthTokens.cipherTextAuthToken[0], computedCipherTextAuthToken.begin(), AUTH_TOKEN_SIZE) !=
	    0) {
		TraceEvent("VerifyEncryptBlobHeader_AuthTokenMismatch")
		    .detail("HeaderVersion", header.flags.headerVersion)
		    .detail("HeaderMode", header.flags.encryptMode)
		    .detail("MultiAuthCipherTextAuthToken",
		            StringRef(arena, &header.multiAuthTokens.cipherTextAuthToken[0], AUTH_TOKEN_SIZE).toString())
		    .detail("ComputedCipherTextAuthToken", computedCipherTextAuthToken.toString());
		throw encrypt_header_authtoken_mismatch();
	}
}

void DecryptBlobCipherAes256Ctr::verifyAuthTokens(const uint8_t* ciphertext,
                                                  const int ciphertextLen,
                                                  const BlobCipherEncryptHeader& header,
                                                  uint8_t* buff,
                                                  Arena& arena) {
	if (header.flags.authTokenMode == ENCRYPT_HEADER_AUTH_TOKEN_MODE_SINGLE) {
		verifyHeaderSingleAuthToken(ciphertext, ciphertextLen, header, buff, arena);
	} else {
		ASSERT_EQ(header.flags.authTokenMode, ENCRYPT_HEADER_AUTH_TOKEN_MODE_MULTI);
		verifyHeaderMultiAuthToken(ciphertext, ciphertextLen, header, buff, arena);
	}

	authTokensValidationDone = true;
}

void DecryptBlobCipherAes256Ctr::verifyEncryptHeaderMetadata(const BlobCipherEncryptHeader& header) {
	// validate header flag sanity
	if (header.flags.headerVersion != EncryptBlobCipherAes265Ctr::ENCRYPT_HEADER_VERSION ||
	    header.flags.encryptMode != ENCRYPT_CIPHER_MODE_AES_256_CTR ||
	    !isEncryptHeaderAuthTokenModeValid((EncryptAuthTokenMode)header.flags.authTokenMode)) {
		TraceEvent("VerifyEncryptBlobHeader")
		    .detail("HeaderVersion", header.flags.headerVersion)
		    .detail("ExpectedVersion", EncryptBlobCipherAes265Ctr::ENCRYPT_HEADER_VERSION)
		    .detail("EncryptCipherMode", header.flags.encryptMode)
		    .detail("ExpectedCipherMode", ENCRYPT_CIPHER_MODE_AES_256_CTR)
		    .detail("EncryptHeaderAuthTokenMode", header.flags.authTokenMode);
		throw encrypt_header_metadata_mismatch();
	}
}

Reference<EncryptBuf> DecryptBlobCipherAes256Ctr::decrypt(const uint8_t* ciphertext,
                                                          const int ciphertextLen,
                                                          const BlobCipherEncryptHeader& header,
                                                          Arena& arena) {
	TEST(true); // Decrypting data with BlobCipher

	verifyEncryptHeaderMetadata(header);

	if (header.flags.authTokenMode != ENCRYPT_HEADER_AUTH_TOKEN_MODE_NONE && !headerCipherKey.isValid()) {
		TraceEvent("Decrypt_InvalidHeaderCipherKey").detail("AuthTokenMode", header.flags.authTokenMode);
		throw encrypt_ops_error();
	}

	const int allocSize = header.flags.authTokenMode == ENCRYPT_HEADER_AUTH_TOKEN_MODE_SINGLE
	                          ? ciphertextLen + AES_BLOCK_SIZE + sizeof(BlobCipherEncryptHeader)
	                          : ciphertextLen + AES_BLOCK_SIZE;
	Reference<EncryptBuf> decrypted = makeReference<EncryptBuf>(allocSize, arena);

	if (header.flags.authTokenMode != ENCRYPT_HEADER_AUTH_TOKEN_MODE_NONE) {
		verifyAuthTokens(ciphertext, ciphertextLen, header, decrypted->begin(), arena);
		ASSERT(authTokensValidationDone);
	}

	uint8_t* plaintext = decrypted->begin();
	int bytesDecrypted{ 0 };
	if (!EVP_DecryptUpdate(ctx, plaintext, &bytesDecrypted, ciphertext, ciphertextLen)) {
		TraceEvent("Decrypt_UpdateFailed")
		    .detail("BaseCipherId", header.cipherTextDetails.baseCipherId)
		    .detail("EncryptDomainId", header.cipherTextDetails.encryptDomainId);
		throw encrypt_ops_error();
	}

	int finalBlobBytes{ 0 };
	if (EVP_DecryptFinal_ex(ctx, plaintext + bytesDecrypted, &finalBlobBytes) <= 0) {
		TraceEvent("Decrypt_FinalFailed")
		    .detail("BaseCipherId", header.cipherTextDetails.baseCipherId)
		    .detail("EncryptDomainId", header.cipherTextDetails.encryptDomainId);
		throw encrypt_ops_error();
	}

	if ((bytesDecrypted + finalBlobBytes) != ciphertextLen) {
		TraceEvent("Encrypt_UnexpectedPlaintextLen")
		    .detail("CiphertextLen", ciphertextLen)
		    .detail("DecryptedBufLen", bytesDecrypted + finalBlobBytes);
		throw encrypt_ops_error();
	}

	decrypted->setLogicalSize(ciphertextLen);
	return decrypted;
}

DecryptBlobCipherAes256Ctr::~DecryptBlobCipherAes256Ctr() {
	if (ctx != nullptr) {
		EVP_CIPHER_CTX_free(ctx);
	}
}

// HmacSha256DigestGen class methods

HmacSha256DigestGen::HmacSha256DigestGen(const unsigned char* key, size_t len) : ctx(HMAC_CTX_new()) {
	if (!HMAC_Init_ex(ctx, key, len, EVP_sha256(), nullptr)) {
		throw encrypt_ops_error();
	}
}

HmacSha256DigestGen::~HmacSha256DigestGen() {
	if (ctx != nullptr) {
		HMAC_CTX_free(ctx);
	}
}

StringRef HmacSha256DigestGen::digest(const unsigned char* data, size_t len, Arena& arena) {
	// TEST(true); // Digest generation
	unsigned int digestLen = HMAC_size(ctx);
	auto digest = new (arena) unsigned char[digestLen];
	if (HMAC_Update(ctx, data, len) != 1) {
		throw encrypt_ops_error();
	}

	if (HMAC_Final(ctx, digest, &digestLen) != 1) {
		throw encrypt_ops_error();
	}
	return StringRef(arena, digest, digestLen);
}

StringRef computeAuthToken(const uint8_t* payload,
                           const int payloadLen,
                           const uint8_t* key,
                           const int keyLen,
                           Arena& arena) {
	HmacSha256DigestGen hmacGenerator(key, keyLen);
	StringRef digest = hmacGenerator.digest(payload, payloadLen, arena);

	ASSERT_GE(digest.size(), AUTH_TOKEN_SIZE);
	return digest;
}

// Only used to link unit tests
void forceLinkBlobCipherTests() {}

// Tests cases includes:
// 1. Populate cache by inserting 'baseCipher' details for new encryptionDomainIds
// 2. Random lookup for cipherKeys and content validation
// 3. Inserting of 'identical' cipherKey (already cached) more than once works as desired.
// 4. Inserting of 'non-identical' cipherKey (already cached) more than once works as desired.
// 5. Validation encryption ops (correctness):
//  5.1. Encrypt a buffer followed by decryption of the buffer, validate the contents.
//  5.2. Simulate anomalies such as: EncryptionHeader corruption, authToken mismatch / encryptionMode mismatch etc.
// 6. Cache cleanup
//  6.1  cleanup cipherKeys by given encryptDomainId
//  6.2. Cleanup all cached cipherKeys
TEST_CASE("flow/BlobCipher") {
	TraceEvent("BlobCipherTest_Start").log();

	// Construct a dummy External Key Manager representation and populate with some keys
	class BaseCipher : public ReferenceCounted<BaseCipher>, NonCopyable {
	public:
		EncryptCipherDomainId domainId;
		int len;
		EncryptCipherBaseKeyId keyId;
		std::unique_ptr<uint8_t[]> key;
		EncryptCipherRandomSalt generatedSalt;

		BaseCipher(const EncryptCipherDomainId& dId, const EncryptCipherBaseKeyId& kId)
		  : domainId(dId), len(deterministicRandom()->randomInt(AES_256_KEY_LENGTH / 2, AES_256_KEY_LENGTH + 1)),
		    keyId(kId), key(std::make_unique<uint8_t[]>(len)) {
			generateRandomData(key.get(), len);
		}
	};

	using BaseKeyMap = std::unordered_map<EncryptCipherBaseKeyId, Reference<BaseCipher>>;
	using DomainKeyMap = std::unordered_map<EncryptCipherDomainId, BaseKeyMap>;
	DomainKeyMap domainKeyMap;
	const EncryptCipherDomainId minDomainId = 1;
	const EncryptCipherDomainId maxDomainId = deterministicRandom()->randomInt(minDomainId, minDomainId + 10) + 5;
	const EncryptCipherBaseKeyId minBaseCipherKeyId = 100;
	const EncryptCipherBaseKeyId maxBaseCipherKeyId =
	    deterministicRandom()->randomInt(minBaseCipherKeyId, minBaseCipherKeyId + 50) + 15;
	for (int dId = minDomainId; dId <= maxDomainId; dId++) {
		for (int kId = minBaseCipherKeyId; kId <= maxBaseCipherKeyId; kId++) {
			domainKeyMap[dId].emplace(kId, makeReference<BaseCipher>(dId, kId));
		}
	}
	ASSERT_EQ(domainKeyMap.size(), maxDomainId);

	Reference<BlobCipherKeyCache> cipherKeyCache = BlobCipherKeyCache::getInstance();

	// validate getLatestCipherKey return empty when there's no cipher key
	TraceEvent("BlobCipherTest_LatestKeyNotExists").log();
	Reference<BlobCipherKey> latestKeyNonexists =
	    cipherKeyCache->getLatestCipherKey(deterministicRandom()->randomInt(minDomainId, maxDomainId));
	ASSERT(!latestKeyNonexists.isValid());
	try {
		cipherKeyCache->getLatestCipherKey(ENCRYPT_INVALID_DOMAIN_ID);
		ASSERT(false); // shouldn't get here
	} catch (Error& e) {
		ASSERT_EQ(e.code(), error_code_encrypt_invalid_id);
	}

	// insert BlobCipher keys into BlobCipherKeyCache map and validate
	TraceEvent("BlobCipherTest_InsertKeys").log();
	for (auto& domainItr : domainKeyMap) {
		for (auto& baseKeyItr : domainItr.second) {
			Reference<BaseCipher> baseCipher = baseKeyItr.second;

			cipherKeyCache->insertCipherKey(
			    baseCipher->domainId, baseCipher->keyId, baseCipher->key.get(), baseCipher->len);
			Reference<BlobCipherKey> fetchedKey = cipherKeyCache->getLatestCipherKey(baseCipher->domainId);
			baseCipher->generatedSalt = fetchedKey->getSalt();
		}
	}
	// insert EncryptHeader BlobCipher key
	Reference<BaseCipher> headerBaseCipher = makeReference<BaseCipher>(ENCRYPT_HEADER_DOMAIN_ID, 1);
	cipherKeyCache->insertCipherKey(
	    headerBaseCipher->domainId, headerBaseCipher->keyId, headerBaseCipher->key.get(), headerBaseCipher->len);

	TraceEvent("BlobCipherTest_InsertKeysDone").log();

	// validate the cipherKey lookups work as desired
	for (auto& domainItr : domainKeyMap) {
		for (auto& baseKeyItr : domainItr.second) {
			Reference<BaseCipher> baseCipher = baseKeyItr.second;
			Reference<BlobCipherKey> cipherKey =
			    cipherKeyCache->getCipherKey(baseCipher->domainId, baseCipher->keyId, baseCipher->generatedSalt);
			ASSERT(cipherKey.isValid());
			// validate common cipher properties - domainId, baseCipherId, baseCipherLen, rawBaseCipher
			ASSERT_EQ(cipherKey->getBaseCipherId(), baseCipher->keyId);
			ASSERT_EQ(cipherKey->getDomainId(), baseCipher->domainId);
			ASSERT_EQ(cipherKey->getBaseCipherLen(), baseCipher->len);
			// ensure that baseCipher matches with the cached information
			ASSERT_EQ(std::memcmp(cipherKey->rawBaseCipher(), baseCipher->key.get(), cipherKey->getBaseCipherLen()), 0);
			// validate the encryption derivation
			ASSERT_NE(std::memcmp(cipherKey->rawCipher(), baseCipher->key.get(), cipherKey->getBaseCipherLen()), 0);
		}
	}
	TraceEvent("BlobCipherTest_LooksupDone").log();

	// Ensure attemtping to insert existing cipherKey (identical) more than once is treated as a NOP
	try {
		Reference<BaseCipher> baseCipher = domainKeyMap[minDomainId][minBaseCipherKeyId];
		cipherKeyCache->insertCipherKey(
		    baseCipher->domainId, baseCipher->keyId, baseCipher->key.get(), baseCipher->len);
	} catch (Error& e) {
		throw;
	}
	TraceEvent("BlobCipherTest_ReinsertIdempotentKeyDone").log();

	// Ensure attemtping to insert an existing cipherKey (modified) fails with appropriate error
	try {
		Reference<BaseCipher> baseCipher = domainKeyMap[minDomainId][minBaseCipherKeyId];
		uint8_t rawCipher[baseCipher->len];
		memcpy(rawCipher, baseCipher->key.get(), baseCipher->len);
		// modify few bytes in the cipherKey
		for (int i = 2; i < 5; i++) {
			rawCipher[i]++;
		}
		cipherKeyCache->insertCipherKey(baseCipher->domainId, baseCipher->keyId, &rawCipher[0], baseCipher->len);
	} catch (Error& e) {
		if (e.code() != error_code_encrypt_update_cipher) {
			throw;
		}
	}
	TraceEvent("BlobCipherTest_ReinsertNonIdempotentKeyDone").log();

	// Validate Encryption ops
	Reference<BlobCipherKey> cipherKey = cipherKeyCache->getLatestCipherKey(minDomainId);
	Reference<BlobCipherKey> headerCipherKey = cipherKeyCache->getLatestCipherKey(ENCRYPT_HEADER_DOMAIN_ID);
	const int bufLen = deterministicRandom()->randomInt(786, 2127) + 512;
	uint8_t orgData[bufLen];
	generateRandomData(&orgData[0], bufLen);

	Arena arena;
	uint8_t iv[AES_256_IV_LENGTH];
	generateRandomData(&iv[0], AES_256_IV_LENGTH);

	BlobCipherEncryptHeader headerCopy;
	// validate basic encrypt followed by decrypt operation for AUTH_MODE_NONE
	{
		TraceEvent("NoneAuthMode_Start").log();

		EncryptBlobCipherAes265Ctr encryptor(
		    cipherKey, Reference<BlobCipherKey>(), iv, AES_256_IV_LENGTH, ENCRYPT_HEADER_AUTH_TOKEN_MODE_NONE);
		BlobCipherEncryptHeader header;
		Reference<EncryptBuf> encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);

		ASSERT_EQ(encrypted->getLogicalSize(), bufLen);
		ASSERT_NE(memcmp(&orgData[0], encrypted->begin(), bufLen), 0);
		ASSERT_EQ(header.flags.headerVersion, EncryptBlobCipherAes265Ctr::ENCRYPT_HEADER_VERSION);
		ASSERT_EQ(header.flags.encryptMode, ENCRYPT_CIPHER_MODE_AES_256_CTR);
		ASSERT_EQ(header.flags.authTokenMode, ENCRYPT_HEADER_AUTH_TOKEN_MODE_NONE);

		TraceEvent("BlobCipherTest_EncryptDone")
		    .detail("HeaderVersion", header.flags.headerVersion)
		    .detail("HeaderEncryptMode", header.flags.encryptMode)
		    .detail("DomainId", header.cipherTextDetails.encryptDomainId)
		    .detail("BaseCipherId", header.cipherTextDetails.baseCipherId);

		Reference<BlobCipherKey> tCipherKeyKey = cipherKeyCache->getCipherKey(header.cipherTextDetails.encryptDomainId,
		                                                                      header.cipherTextDetails.baseCipherId,
		                                                                      header.cipherTextDetails.salt);
		ASSERT(tCipherKeyKey->isEqual(cipherKey));
		DecryptBlobCipherAes256Ctr decryptor(tCipherKeyKey, Reference<BlobCipherKey>(), &header.iv[0]);
		Reference<EncryptBuf> decrypted = decryptor.decrypt(encrypted->begin(), bufLen, header, arena);

		ASSERT_EQ(decrypted->getLogicalSize(), bufLen);
		ASSERT_EQ(memcmp(decrypted->begin(), &orgData[0], bufLen), 0);

		TraceEvent("BlobCipherTest_DecryptDone").log();

		// induce encryption header corruption - headerVersion corrupted
		memcpy(reinterpret_cast<uint8_t*>(&headerCopy),
		       reinterpret_cast<const uint8_t*>(&header),
		       sizeof(BlobCipherEncryptHeader));
		headerCopy.flags.headerVersion += 1;
		try {
			encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);
			DecryptBlobCipherAes256Ctr decryptor(tCipherKeyKey, Reference<BlobCipherKey>(), header.iv);
			decrypted = decryptor.decrypt(encrypted->begin(), bufLen, headerCopy, arena);
			ASSERT(false); // error expected
		} catch (Error& e) {
			if (e.code() != error_code_encrypt_header_metadata_mismatch) {
				throw;
			}
		}

		// induce encryption header corruption - encryptionMode corrupted
		memcpy(reinterpret_cast<uint8_t*>(&headerCopy),
		       reinterpret_cast<const uint8_t*>(&header),
		       sizeof(BlobCipherEncryptHeader));
		headerCopy.flags.encryptMode += 1;
		try {
			encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);
			DecryptBlobCipherAes256Ctr decryptor(tCipherKeyKey, Reference<BlobCipherKey>(), header.iv);
			decrypted = decryptor.decrypt(encrypted->begin(), bufLen, headerCopy, arena);
			ASSERT(false); // error expected
		} catch (Error& e) {
			if (e.code() != error_code_encrypt_header_metadata_mismatch) {
				throw;
			}
		}

		// induce encrypted buffer payload corruption
		try {
			encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);
			uint8_t temp[bufLen];
			memcpy(encrypted->begin(), &temp[0], bufLen);
			int tIdx = deterministicRandom()->randomInt(0, bufLen - 1);
			temp[tIdx] += 1;
			DecryptBlobCipherAes256Ctr decryptor(tCipherKeyKey, Reference<BlobCipherKey>(), header.iv);
			decrypted = decryptor.decrypt(&temp[0], bufLen, header, arena);
		} catch (Error& e) {
			// No authToken, hence, no corruption detection supported
			ASSERT(false);
		}

		TraceEvent("NoneAuthMode_Done").log();
	}

	// validate basic encrypt followed by decrypt operation for AUTH_TOKEN_MODE_SINGLE
	{
		TraceEvent("SingleAuthMode_Start").log();

		EncryptBlobCipherAes265Ctr encryptor(
		    cipherKey, headerCipherKey, iv, AES_256_IV_LENGTH, ENCRYPT_HEADER_AUTH_TOKEN_MODE_SINGLE);
		BlobCipherEncryptHeader header;
		Reference<EncryptBuf> encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);

		ASSERT_EQ(encrypted->getLogicalSize(), bufLen);
		ASSERT_NE(memcmp(&orgData[0], encrypted->begin(), bufLen), 0);
		ASSERT_EQ(header.flags.headerVersion, EncryptBlobCipherAes265Ctr::ENCRYPT_HEADER_VERSION);
		ASSERT_EQ(header.flags.encryptMode, ENCRYPT_CIPHER_MODE_AES_256_CTR);
		ASSERT_EQ(header.flags.authTokenMode, ENCRYPT_HEADER_AUTH_TOKEN_MODE_SINGLE);

		TraceEvent("BlobCipherTest_EncryptDone")
		    .detail("HeaderVersion", header.flags.headerVersion)
		    .detail("HeaderEncryptMode", header.flags.encryptMode)
		    .detail("DomainId", header.cipherTextDetails.encryptDomainId)
		    .detail("BaseCipherId", header.cipherTextDetails.baseCipherId)
		    .detail("HeaderAuthToken",
		            StringRef(arena, &header.singleAuthToken.authToken[0], AUTH_TOKEN_SIZE).toString());

		Reference<BlobCipherKey> tCipherKeyKey = cipherKeyCache->getCipherKey(header.cipherTextDetails.encryptDomainId,
		                                                                      header.cipherTextDetails.baseCipherId,
		                                                                      header.cipherTextDetails.salt);
		Reference<BlobCipherKey> hCipherKey = cipherKeyCache->getCipherKey(header.cipherHeaderDetails.encryptDomainId,
		                                                                   header.cipherHeaderDetails.baseCipherId,
		                                                                   header.cipherHeaderDetails.salt);
		ASSERT(tCipherKeyKey->isEqual(cipherKey));
		DecryptBlobCipherAes256Ctr decryptor(tCipherKeyKey, hCipherKey, header.iv);
		Reference<EncryptBuf> decrypted = decryptor.decrypt(encrypted->begin(), bufLen, header, arena);

		ASSERT_EQ(decrypted->getLogicalSize(), bufLen);
		ASSERT_EQ(memcmp(decrypted->begin(), &orgData[0], bufLen), 0);

		TraceEvent("BlobCipherTest_DecryptDone").log();

		// induce encryption header corruption - headerVersion corrupted
		encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);
		memcpy(reinterpret_cast<uint8_t*>(&headerCopy),
		       reinterpret_cast<const uint8_t*>(&header),
		       sizeof(BlobCipherEncryptHeader));
		headerCopy.flags.headerVersion += 1;
		try {
			DecryptBlobCipherAes256Ctr decryptor(tCipherKeyKey, hCipherKey, header.iv);
			decrypted = decryptor.decrypt(encrypted->begin(), bufLen, headerCopy, arena);
			ASSERT(false); // error expected
		} catch (Error& e) {
			if (e.code() != error_code_encrypt_header_metadata_mismatch) {
				throw;
			}
		}

		// induce encryption header corruption - encryptionMode corrupted
		encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);
		memcpy(reinterpret_cast<uint8_t*>(&headerCopy),
		       reinterpret_cast<const uint8_t*>(&header),
		       sizeof(BlobCipherEncryptHeader));
		headerCopy.flags.encryptMode += 1;
		try {
			DecryptBlobCipherAes256Ctr decryptor(tCipherKeyKey, hCipherKey, header.iv);
			decrypted = decryptor.decrypt(encrypted->begin(), bufLen, headerCopy, arena);
			ASSERT(false); // error expected
		} catch (Error& e) {
			if (e.code() != error_code_encrypt_header_metadata_mismatch) {
				throw;
			}
		}

		// induce encryption header corruption - authToken mismatch
		encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);
		memcpy(reinterpret_cast<uint8_t*>(&headerCopy),
		       reinterpret_cast<const uint8_t*>(&header),
		       sizeof(BlobCipherEncryptHeader));
		int hIdx = deterministicRandom()->randomInt(0, AUTH_TOKEN_SIZE - 1);
		headerCopy.singleAuthToken.authToken[hIdx] += 1;
		try {
			DecryptBlobCipherAes256Ctr decryptor(tCipherKeyKey, hCipherKey, header.iv);
			decrypted = decryptor.decrypt(encrypted->begin(), bufLen, headerCopy, arena);
			ASSERT(false); // error expected
		} catch (Error& e) {
			if (e.code() != error_code_encrypt_header_authtoken_mismatch) {
				throw;
			}
		}

		// induce encrypted buffer payload corruption
		try {
			encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);
			uint8_t temp[bufLen];
			memcpy(encrypted->begin(), &temp[0], bufLen);
			int tIdx = deterministicRandom()->randomInt(0, bufLen - 1);
			temp[tIdx] += 1;
			DecryptBlobCipherAes256Ctr decryptor(tCipherKeyKey, hCipherKey, header.iv);
			decrypted = decryptor.decrypt(&temp[0], bufLen, header, arena);
		} catch (Error& e) {
			if (e.code() != error_code_encrypt_header_authtoken_mismatch) {
				throw;
			}
		}

		TraceEvent("SingleAuthMode_Done").log();
	}

	// validate basic encrypt followed by decrypt operation for AUTH_TOKEN_MODE_MULTI
	{
		TraceEvent("MultiAuthMode_Start").log();

		EncryptBlobCipherAes265Ctr encryptor(
		    cipherKey, headerCipherKey, iv, AES_256_IV_LENGTH, ENCRYPT_HEADER_AUTH_TOKEN_MODE_MULTI);
		BlobCipherEncryptHeader header;
		Reference<EncryptBuf> encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);

		ASSERT_EQ(encrypted->getLogicalSize(), bufLen);
		ASSERT_NE(memcmp(&orgData[0], encrypted->begin(), bufLen), 0);
		ASSERT_EQ(header.flags.headerVersion, EncryptBlobCipherAes265Ctr::ENCRYPT_HEADER_VERSION);
		ASSERT_EQ(header.flags.encryptMode, ENCRYPT_CIPHER_MODE_AES_256_CTR);
		ASSERT_EQ(header.flags.authTokenMode, ENCRYPT_HEADER_AUTH_TOKEN_MODE_MULTI);

		TraceEvent("BlobCipherTest_EncryptDone")
		    .detail("HeaderVersion", header.flags.headerVersion)
		    .detail("HeaderEncryptMode", header.flags.encryptMode)
		    .detail("DomainId", header.cipherTextDetails.encryptDomainId)
		    .detail("BaseCipherId", header.cipherTextDetails.baseCipherId)
		    .detail("HeaderAuthToken",
		            StringRef(arena, &header.singleAuthToken.authToken[0], AUTH_TOKEN_SIZE).toString());

		Reference<BlobCipherKey> tCipherKey = cipherKeyCache->getCipherKey(header.cipherTextDetails.encryptDomainId,
		                                                                   header.cipherTextDetails.baseCipherId,
		                                                                   header.cipherTextDetails.salt);
		Reference<BlobCipherKey> hCipherKey = cipherKeyCache->getCipherKey(header.cipherHeaderDetails.encryptDomainId,
		                                                                   header.cipherHeaderDetails.baseCipherId,
		                                                                   header.cipherHeaderDetails.salt);

		ASSERT(tCipherKey->isEqual(cipherKey));
		DecryptBlobCipherAes256Ctr decryptor(tCipherKey, hCipherKey, header.iv);
		Reference<EncryptBuf> decrypted = decryptor.decrypt(encrypted->begin(), bufLen, header, arena);

		ASSERT_EQ(decrypted->getLogicalSize(), bufLen);
		ASSERT_EQ(memcmp(decrypted->begin(), &orgData[0], bufLen), 0);

		TraceEvent("BlobCipherTest_DecryptDone").log();

		// induce encryption header corruption - headerVersion corrupted
		encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);
		memcpy(reinterpret_cast<uint8_t*>(&headerCopy),
		       reinterpret_cast<const uint8_t*>(&header),
		       sizeof(BlobCipherEncryptHeader));
		headerCopy.flags.headerVersion += 1;
		try {
			DecryptBlobCipherAes256Ctr decryptor(tCipherKey, hCipherKey, header.iv);
			decrypted = decryptor.decrypt(encrypted->begin(), bufLen, headerCopy, arena);
			ASSERT(false); // error expected
		} catch (Error& e) {
			if (e.code() != error_code_encrypt_header_metadata_mismatch) {
				throw;
			}
		}

		// induce encryption header corruption - encryptionMode corrupted
		encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);
		memcpy(reinterpret_cast<uint8_t*>(&headerCopy),
		       reinterpret_cast<const uint8_t*>(&header),
		       sizeof(BlobCipherEncryptHeader));
		headerCopy.flags.encryptMode += 1;
		try {
			DecryptBlobCipherAes256Ctr decryptor(tCipherKey, hCipherKey, header.iv);
			decrypted = decryptor.decrypt(encrypted->begin(), bufLen, headerCopy, arena);
			ASSERT(false); // error expected
		} catch (Error& e) {
			if (e.code() != error_code_encrypt_header_metadata_mismatch) {
				throw;
			}
		}

		// induce encryption header corruption - cipherText authToken mismatch
		encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);
		memcpy(reinterpret_cast<uint8_t*>(&headerCopy),
		       reinterpret_cast<const uint8_t*>(&header),
		       sizeof(BlobCipherEncryptHeader));
		int hIdx = deterministicRandom()->randomInt(0, AUTH_TOKEN_SIZE - 1);
		headerCopy.multiAuthTokens.cipherTextAuthToken[hIdx] += 1;
		try {
			DecryptBlobCipherAes256Ctr decryptor(tCipherKey, hCipherKey, header.iv);
			decrypted = decryptor.decrypt(encrypted->begin(), bufLen, headerCopy, arena);
			ASSERT(false); // error expected
		} catch (Error& e) {
			if (e.code() != error_code_encrypt_header_authtoken_mismatch) {
				throw;
			}
		}

		// induce encryption header corruption - header authToken mismatch
		encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);
		memcpy(reinterpret_cast<uint8_t*>(&headerCopy),
		       reinterpret_cast<const uint8_t*>(&header),
		       sizeof(BlobCipherEncryptHeader));
		hIdx = deterministicRandom()->randomInt(0, AUTH_TOKEN_SIZE - 1);
		headerCopy.multiAuthTokens.headerAuthToken[hIdx] += 1;
		try {
			DecryptBlobCipherAes256Ctr decryptor(tCipherKey, hCipherKey, header.iv);
			decrypted = decryptor.decrypt(encrypted->begin(), bufLen, headerCopy, arena);
			ASSERT(false); // error expected
		} catch (Error& e) {
			if (e.code() != error_code_encrypt_header_authtoken_mismatch) {
				throw;
			}
		}

		try {
			encrypted = encryptor.encrypt(&orgData[0], bufLen, &header, arena);
			uint8_t temp[bufLen];
			memcpy(encrypted->begin(), &temp[0], bufLen);
			int tIdx = deterministicRandom()->randomInt(0, bufLen - 1);
			temp[tIdx] += 1;
			DecryptBlobCipherAes256Ctr decryptor(tCipherKey, hCipherKey, header.iv);
			decrypted = decryptor.decrypt(&temp[0], bufLen, header, arena);
		} catch (Error& e) {
			if (e.code() != error_code_encrypt_header_authtoken_mismatch) {
				throw;
			}
		}

		TraceEvent("MultiAuthMode_Done").log();
	}

	// Validate dropping encryptDomainId cached keys
	const EncryptCipherDomainId candidate = deterministicRandom()->randomInt(minDomainId, maxDomainId);
	cipherKeyCache->resetEncryptDomainId(candidate);
	std::vector<Reference<BlobCipherKey>> cachedKeys = cipherKeyCache->getAllCiphers(candidate);
	ASSERT(cachedKeys.empty());

	// Validate dropping all cached cipherKeys
	cipherKeyCache->cleanup();
	for (int dId = minDomainId; dId < maxDomainId; dId++) {
		std::vector<Reference<BlobCipherKey>> cachedKeys = cipherKeyCache->getAllCiphers(dId);
		ASSERT(cachedKeys.empty());
	}

	TraceEvent("BlobCipherTest_Done").log();
	return Void();
}
