/*
 * BlobGranuleCommon.h
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

#ifndef FDBCLIENT_BLOBGRANULECOMMON_H
#define FDBCLIENT_BLOBGRANULECOMMON_H
#include "flow/BlobCipher.h"
#include "flow/IRandom.h"
#include "flow/serialize.h"
#pragma once

#include <sstream>

#include "fdbclient/CommitTransaction.h"
#include "fdbclient/FDBTypes.h"

// file format of actual blob files
// FIXME: use VecSerStrategy::String serialization for this
struct GranuleSnapshot : VectorRef<KeyValueRef> {

	constexpr static FileIdentifier file_identifier = 1300395;

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, ((VectorRef<KeyValueRef>&)*this));
	}
};

struct GranuleDeltas : VectorRef<MutationsAndVersionRef> {
	constexpr static FileIdentifier file_identifier = 8563013;

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, ((VectorRef<MutationsAndVersionRef>&)*this));
	}
};

struct BlobGranuleCipherKeysMeta {
	BlobCipherDetails textCipherDetails;
	BlobCipherDetails headerCipherDetails;
	StringRef ivRef;

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, textCipherDetails, headerCipherDetails, ivRef);
	}
};

struct BlobGranuleCipherKey {
	BlobCipherDetails cipherDetails;
	StringRef baseCipher;

	static BlobGranuleCipherKey fromBlobCipherKey(Reference<BlobCipherKey> keyRef, Arena& arena) {
		BlobGranuleCipherKey cipherKey;

		cipherKey.cipherDetails.encryptDomainId = keyRef->getDomainId();
		cipherKey.cipherDetails.baseCipherId = keyRef->getBaseCipherId();
		cipherKey.cipherDetails.salt = keyRef->getSalt();
		cipherKey.baseCipher = makeString(keyRef->getBaseCipherLen(), arena);
		memcpy(mutateString(cipherKey.baseCipher), keyRef->rawBaseCipher(), keyRef->getBaseCipherLen());
		return cipherKey;
	}

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, cipherDetails, baseCipher);
	}
};

struct BlobGranuleCipherKeysCtx {
	BlobGranuleCipherKey textCipherKey;
	BlobGranuleCipherKey headerCipherKey;
	StringRef ivRef;

	BlobGranuleCipherKeysMeta toCipherKeysMeta(Arena& arena) {
		BlobGranuleCipherKeysMeta cipherKeysMeta;

		cipherKeysMeta.textCipherDetails = textCipherKey.cipherDetails;
		cipherKeysMeta.headerCipherDetails = headerCipherKey.cipherDetails;
		cipherKeysMeta.ivRef = makeString(AES_256_IV_LENGTH, arena);
		generateRandomData(mutateString(cipherKeysMeta.ivRef), AES_256_IV_LENGTH);
		return cipherKeysMeta;
	}

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, textCipherKey, headerCipherKey, ivRef);
	}
};

struct BlobFilePointerRef {
	constexpr static FileIdentifier file_identifier = 5253554;
	StringRef filename;
	int64_t offset;
	int64_t length;
	int64_t fullFileLength;
	Optional<BlobGranuleCipherKeysMeta> cipherKeysMeta;

	BlobFilePointerRef() {}

	BlobFilePointerRef(Arena& to, const std::string& filename, int64_t offset, int64_t length, int64_t fullFileLength)
	  : filename(to, filename), offset(offset), length(length), fullFileLength(fullFileLength) {}

	BlobFilePointerRef(Arena& to,
	                   const std::string& filename,
	                   int64_t offset,
	                   int64_t length,
	                   int64_t fullFileLength,
	                   Optional<BlobGranuleCipherKeysMeta> ciphKeysMeta)
	  : filename(to, filename), offset(offset), length(length), fullFileLength(fullFileLength),
	    cipherKeysMeta(ciphKeysMeta) {}

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, filename, offset, length, fullFileLength, cipherKeysMeta);
	}

	std::string toString() const {
		std::stringstream ss;
		ss << filename.toString() << ":" << offset << ":" << length << ":" << fullFileLength;
		if (cipherKeysMeta.present()) {
			ss << ":CipherKeysMeta:TextCipher:" << cipherKeysMeta.get().textCipherDetails.encryptDomainId << ":"
			   << cipherKeysMeta.get().textCipherDetails.baseCipherId << ":"
			   << cipherKeysMeta.get().textCipherDetails.salt
			   << ":HeaderCipher:" << cipherKeysMeta.get().headerCipherDetails.encryptDomainId << ":"
			   << cipherKeysMeta.get().headerCipherDetails.baseCipherId << ":"
			   << cipherKeysMeta.get().headerCipherDetails.salt;
		}
		return std::move(ss).str();
	}
};

// the assumption of this response is that the client will deserialize the files and apply the mutations themselves
// TODO could filter out delta files that don't intersect the key range being requested?
// TODO since client request passes version, we don't need to include the version of each mutation in the response if we
// pruned it there
struct BlobGranuleChunkRef {
	constexpr static FileIdentifier file_identifier = 865198;
	KeyRangeRef keyRange;
	Version includedVersion;
	Version snapshotVersion;
	Optional<BlobFilePointerRef> snapshotFile; // not set if it's an incremental read
	VectorRef<BlobFilePointerRef> deltaFiles;
	GranuleDeltas newDeltas;
	Optional<KeyRef> tenantPrefix;
	Optional<BlobGranuleCipherKeysCtx> cipherKeysCtx;

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar,
		           keyRange,
		           includedVersion,
		           snapshotVersion,
		           snapshotFile,
		           deltaFiles,
		           newDeltas,
		           tenantPrefix,
		           cipherKeysCtx);
	}
};

enum BlobGranuleSplitState { Unknown = 0, Initialized = 1, Assigned = 2, Done = 3 };

struct BlobGranuleHistoryValue {
	constexpr static FileIdentifier file_identifier = 991434;
	UID granuleID;
	VectorRef<std::pair<KeyRangeRef, Version>> parentGranules;

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, granuleID, parentGranules);
	}
};

#endif
