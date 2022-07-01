/*
 * BlobGranuleFiles.cpp
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

#include <cstring>
#include <vector>

#include "contrib/fmt-8.1.1/include/fmt/format.h"
#include "fdbclient/BlobGranuleCommon.h"
#include "fdbclient/ClientKnobs.h"
#include "fdbclient/ServerKnobs.h"
#include "fdbserver/Knobs.h"
#include "flow/Arena.h"
#include "flow/BlobCipher.h"
#include "flow/CompressionUtils.h"
#include "flow/DeterministicRandom.h"
#include "flow/EncryptUtils.h"
#include "flow/Error.h"
#include "flow/FastRef.h"
#include "flow/FileIdentifier.h"
#include "flow/IRandom.h"
#include "flow/ObjectSerializer.h"
#include "flow/StreamCipher.h"
#include "flow/TreeBenchmark.h"
#include "flow/serialize.h"
#include "fdbclient/BlobGranuleFiles.h"
#include "fdbclient/Knobs.h"
#include "fdbclient/SystemData.h" // for allKeys unit test - could remove
#include "flow/UnitTest.h"

#define BG_READ_DEBUG false

// FIXME: implement actual proper file format for this

// Implements granule file parsing and materialization with normal c++ functions (non-actors) so that this can be used
// outside the FDB network thread.

// File Format stuff

// Version info for file format of chunked files.
uint16_t LATEST_BG_FORMAT_VERSION = 1;
uint16_t MIN_SUPPORTED_BG_FORMAT_VERSION = 1;

// TODO combine with SystemData? These don't actually have to match though

const uint8_t SNAPSHOT_FILE_TYPE = 'S';
const uint8_t DELTA_FILE_TYPE = 'D';

struct ChildBlockPointerRef {
	StringRef key;
	uint32_t offset;

	ChildBlockPointerRef() {}
	explicit ChildBlockPointerRef(StringRef key, uint32_t offset) : key(key), offset(offset) {}
	explicit ChildBlockPointerRef(Arena& arena, StringRef key, uint32_t offset) : key(arena, key), offset(offset) {}

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, key, offset);
	}

	struct OrderByKey {
		bool operator()(ChildBlockPointerRef const& a, ChildBlockPointerRef const& b) const { return a.key < b.key; }
	};

	struct OrderByKeyCommonPrefix {
		int prefixLen;
		OrderByKeyCommonPrefix(int prefixLen) : prefixLen(prefixLen) {}
		bool operator()(ChildBlockPointerRef const& a, ChildBlockPointerRef const& b) const {
			return a.key.compareSuffix(b.key, prefixLen);
		}
	};
};

struct IndexBlockRef {
	constexpr static FileIdentifier file_identifier = 1945731;

	VectorRef<ChildBlockPointerRef> children;

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, children);
	}
};

struct BlobGranuleEncryptedStringRef {
	constexpr static FileIdentifier file_identifier = 1175274;

	// Serializable fields
	uint8_t encryptMode;
	StringRef header;
	StringRef buffer;

	// Non-serializable fields
	Optional<BlobCipherEncryptHeader> encryptionHeader;
	Optional<Reference<EncryptBlobCipherAes265Ctr>> encryptor;
	Optional<Reference<DecryptBlobCipherAes256Ctr>> decryptor;

	BlobGranuleEncryptedStringRef() { encryptMode = encryptModeFromString(SERVER_KNOBS->ENCRYPTION_MODE); }

	StringRef decrypt(BlobGranuleCipherKeysCtx cipherKeysCtx, StringRef encryptedBuff, Arena& arena) {
		// Ensure sanity of the on-disk 'encryption header'
		validateHeader(cipherKeysCtx, arena);

		// TODO: optimize memcpy operations
		Reference<EncryptBuf> decrypted =
		    decryptor.get()->decrypt(encryptedBuff.begin(), encryptedBuff.size(), encryptionHeader.get(), arena);
		return StringRef(arena, decrypted->begin(), decrypted->getLogicalSize());
	}

	Value encryptChunk(BlobGranuleCipherKeysCtx cipherKeysCtx, Value chunk) {
		if (!encryptor.present() || !encryptor.get().isValid()) {
			initEncryptor(cipherKeysCtx);
			ASSERT(encryptor.present() && encryptor.get().isValid());
		}

		return encryptor.get()->encryptBlobGranuleChunk(chunk.begin(), chunk.size());
	}

	void updateHeaderAndBuffer(BlobGranuleCipherKeysCtx cipherKeysCtx, StringRef encryptedBuff) {
		if (!encryptor.present() || !encryptor.get().isValid()) {
			initEncryptor(cipherKeysCtx);
			ASSERT(encryptor.present() && encryptor.get().isValid());
		}

		header = encryptor.get()->generateBlobFileEncryptionHeader(encryptedBuff);
		buffer = encryptedBuff;
	}

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, header, buffer);
	}

private:
	void initEncryptor(BlobGranuleCipherKeysCtx cipherKeysCtx) {
		Reference<BlobCipherKey> textCipherKey = makeReference<BlobCipherKey>(cipherKeysCtx.textCipherKey.cipherDetails,
		                                                                      cipherKeysCtx.textCipherKey.baseCipher);
		Reference<BlobCipherKey> headerCipherKey = makeReference<BlobCipherKey>(
		    cipherKeysCtx.headerCipherKey.cipherDetails, cipherKeysCtx.headerCipherKey.baseCipher);
		encryptor = makeReference<EncryptBlobCipherAes265Ctr>(textCipherKey,
		                                                      headerCipherKey,
		                                                      cipherKeysCtx.ivRef.begin(),
		                                                      cipherKeysCtx.ivRef.size(),
		                                                      ENCRYPT_HEADER_AUTH_TOKEN_MODE_MULTI);
	}

	void initDecryptor(BlobGranuleCipherKeysCtx cipherKeysCtx) {
		Reference<BlobCipherKey> textCipherKey = makeReference<BlobCipherKey>(cipherKeysCtx.textCipherKey.cipherDetails,
		                                                                      cipherKeysCtx.textCipherKey.baseCipher);
		Reference<BlobCipherKey> headerCipherKey = makeReference<BlobCipherKey>(
		    cipherKeysCtx.headerCipherKey.cipherDetails, cipherKeysCtx.headerCipherKey.baseCipher);
		decryptor =
		    makeReference<DecryptBlobCipherAes256Ctr>(textCipherKey, headerCipherKey, cipherKeysCtx.ivRef.begin());
	}

	void validateHeader(BlobGranuleCipherKeysCtx cipherKeysCtx, Arena& arena) {
		if (decryptor.present() && decryptor.get().isValid()) {
			// Encryption header already validated; do nothing.
			return;
		}

		encryptionHeader = BlobCipherEncryptHeader::fromStringRef(header);
		if (encryptionHeader.get().flags.authTokenMode !=
		        ENCRYPT_HEADER_AUTH_TOKEN_MODE_MULTI || // BlobFiles should have MultiAuthToken mode set
		    !(cipherKeysCtx.headerCipherKey.cipherDetails == encryptionHeader.get().cipherHeaderDetails) ||
		    !(cipherKeysCtx.textCipherKey.cipherDetails == encryptionHeader.get().cipherTextDetails) ||
		    memcmp(cipherKeysCtx.ivRef.begin(), &encryptionHeader.get().iv[0], AES_256_IV_LENGTH) != 0) {
			throw encrypt_header_metadata_mismatch();
		}

		initDecryptor(cipherKeysCtx);
		ASSERT(decryptor.present() && decryptor.get().isValid());

		decryptor.get()->verifyHeaderAuthToken(encryptionHeader.get(), arena);
	}
};

/*
 * A file header for a key-ordered file that is chunked on disk, where each chunk is a disjoint key range of data.
 * FIXME: encryption and compression support
 */
struct IndexedBlobGranuleFile {
	constexpr static FileIdentifier file_identifier = 3828201;
	// serialized fields
	uint16_t formatVersion;
	uint8_t fileType;
	Optional<StringRef> filter; // not used currently

	Optional<BlobGranuleEncryptedStringRef> encrypted;
	CompressionFilter compressionFilter;
	Optional<IndexBlockRef> indexBlock;

	// Non-serialized member fields
	StringRef fileBytes;

	void init(Optional<BlobGranuleCipherKeysCtx> cipherKeysCtx) {
		formatVersion = LATEST_BG_FORMAT_VERSION;
		fileType = SNAPSHOT_FILE_TYPE;

		if (SERVER_KNOBS->ENABLE_BLOB_FILE_COMPRESSION) {
			compressionFilter = CompressionUtils::fromFilterString(SERVER_KNOBS->BLOB_FILE_COMPRESSION_FILTER);
		} else {
			compressionFilter = CompressionFilter::NONE;
		}

		if (cipherKeysCtx.present()) {
			ASSERT(SERVER_KNOBS->ENABLE_BLOB_FILE_ENCRYPTION);
			encrypted = BlobGranuleEncryptedStringRef();
		}

		indexBlock = IndexBlockRef();
	}

	void init(const StringRef& fBytes, Arena& arena, Optional<BlobGranuleCipherKeysCtx> cipherKeysCtx) {
		fileBytes = fBytes;

		if (encrypted.present()) {
			ASSERT(cipherKeysCtx.present());
			ASSERT(!indexBlock.present());
			ASSERT(encrypted.get().encryptMode == ENCRYPT_CIPHER_MODE_AES_256_CTR);

			IndexBlockRef idxRef;
			ObjectReader dataReader(encrypted.get().decrypt(cipherKeysCtx.get(), encrypted.get().buffer, arena).begin(),
			                        Unversioned());
			dataReader.deserialize(FileIdentifierFor<IndexBlockRef>::value, idxRef, arena);
			indexBlock = idxRef;
		} else {
			ASSERT(indexBlock.present());
		}
		TraceEvent("IndexedBlobGranuleFiles_Init");
	}

	bool isChunkCompressed() { return compressionFilter != CompressionFilter::NONE; }

	Value compressChunkIfEnabled(Value chunk) {
		if (compressionFilter == CompressionFilter::NONE) {
			return chunk;
		}
		return CompressionUtils::compress(compressionFilter, chunk);
	}

	Value uncompressChunk(StringRef buffer, Arena& arena) {
		ASSERT(isChunkCompressed());

		return CompressionUtils::decompress(compressionFilter, buffer, arena);
	}

	Value encryptChunkIfEnabled(Optional<BlobGranuleCipherKeysCtx> cipherKeysCtx, Value chunk) {
		if (!encrypted.present()) {
			return chunk;
		}

		ASSERT(SERVER_KNOBS->ENABLE_BLOB_FILE_ENCRYPTION);
		ASSERT(cipherKeysCtx.present());

		return encrypted.get().encryptChunk(cipherKeysCtx.get(), chunk);
	}

	Value decryptChunk(BlobGranuleCipherKeysCtx cipherKeysCtx, StringRef buffer, Arena& arena) {
		ASSERT(encrypted.present());

		return encrypted.get().decrypt(cipherKeysCtx, buffer, arena);
	}

	static Standalone<IndexedBlobGranuleFile> fromFileBytes(const StringRef& fileBytes,
	                                                        Optional<BlobGranuleCipherKeysCtx> cipherKeysCtx) {
		// parse index block at head of file
		Arena arena;
		IndexedBlobGranuleFile file;
		// TODO: version?
		ObjectReader dataReader(fileBytes.begin(), Unversioned());
		dataReader.deserialize(FileIdentifierFor<IndexedBlobGranuleFile>::value, file, arena);

		file.init(fileBytes, arena, cipherKeysCtx);
		ASSERT(file.indexBlock.present());

		// do sanity checks
		if (file.formatVersion > LATEST_BG_FORMAT_VERSION || file.formatVersion < MIN_SUPPORTED_BG_FORMAT_VERSION) {
			TraceEvent(SevWarn, "BlobGranuleFileInvalidFormatVersion")
			    .suppressFor(5.0)
			    .detail("FoundFormatVersion", file.formatVersion)
			    .detail("MinSupported", MIN_SUPPORTED_BG_FORMAT_VERSION)
			    .detail("LatestSupported", LATEST_BG_FORMAT_VERSION);
			throw unsupported_format_version();
		}
		ASSERT(file.fileType == SNAPSHOT_FILE_TYPE || file.fileType == DELTA_FILE_TYPE);

		return Standalone<IndexedBlobGranuleFile>(file, arena);
	}

	ChildBlockPointerRef* findStartBlock(const KeyRef& beginKey) const {
		ASSERT(indexBlock.present());

		ChildBlockPointerRef searchKey(beginKey, 0);
		ChildBlockPointerRef* startBlock = (ChildBlockPointerRef*)std::lower_bound(indexBlock.get().children.begin(),
		                                                                           indexBlock.get().children.end(),
		                                                                           searchKey,
		                                                                           ChildBlockPointerRef::OrderByKey());

		if (startBlock != indexBlock.get().children.end() && startBlock != indexBlock.get().children.begin() &&
		    beginKey < startBlock->key) {
			startBlock--;
		} else if (startBlock == indexBlock.get().children.end()) {
			startBlock--;
		}

		return startBlock;
	}

	// FIXME: implement some sort of iterator type interface?
	template <class ChildType>
	Standalone<ChildType> getChild(const ChildBlockPointerRef* childPointer,
	                               Optional<BlobGranuleCipherKeysCtx> cipherKeysCtx) {
		ASSERT(indexBlock.present());

		ASSERT(childPointer != indexBlock.get().children.end());
		const ChildBlockPointerRef* nextPointer = childPointer + 1;
		ASSERT(nextPointer != indexBlock.get().children.end());

		size_t blockSize = nextPointer->offset - childPointer->offset;
		StringRef childData(fileBytes.begin() + childPointer->offset, blockSize);

		Arena childArena;

		if (encrypted.present()) {
			ASSERT(cipherKeysCtx.present());
			childData = decryptChunk(cipherKeysCtx.get(), childData, childArena);
		}

		if (isChunkCompressed()) {
			childData = uncompressChunk(childData, childArena);
		}

		// TODO: version?
		ChildType child;
		ObjectReader dataReader(childData.begin(), Unversioned());
		dataReader.deserialize(FileIdentifierFor<ChildType>::value, child, childArena);

		// TODO implement some sort of decrypted+decompressed+deserialized cache, if this object gets reused?
		return Standalone<ChildType>(child, childArena);
	}

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, formatVersion, fileType, encrypted, compressionFilter, indexBlock);
	}
};

// Since ObjectReader doesn't update read offset after reading, we have to make the block offsets absolute offsets by
// serializing once, adding the serialized size to each offset, and serializing again. This relies on the fact that
// ObjectWriter/flatbuffers uses fixed size integers instead of variable size.

Value serializeIndexBlock(Standalone<IndexedBlobGranuleFile>& file, Optional<BlobGranuleCipherKeysCtx> cipherKeysCtx) {
	ASSERT(file.indexBlock.present());

	// TODO: version?
	Value indexBlock = ObjectWriter::toValue(file, Unversioned());
	for (auto& it : file.indexBlock.get().children) {
		it.offset += indexBlock.size();
	}

	// NOTE: Above loop updated the indexBlock childBlock pointers offsets to be relative to IndexBlock endOffset
	// instead of file start offset; compressing indexBlock will need offset recalculation (circular depedency).
	// IndexBlock size is bounded by number of chunks and sizeof(KeyPrefix), 'not' compressing IndexBlock shouldn't
	// cause significant file size bloat.
	if (file.encrypted.present()) {
		ASSERT(cipherKeysCtx.present());

		Value toSerialize = ObjectWriter::toValue(file.indexBlock, Unversioned());
		file.encrypted.get().updateHeaderAndBuffer(cipherKeysCtx.get(),
		                                           file.encryptChunkIfEnabled(cipherKeysCtx.get(), toSerialize));
		file.indexBlock.reset();
	}

	TraceEvent("AfterSerializeIndexBlock").log();

	return ObjectWriter::toValue(file, Unversioned());
}

// TODO: this should probably be in actor file with yields?
// TODO: optimize memory copying
// TODO: sanity check no oversized files
Value serializeChunkedSnapshot(Standalone<GranuleSnapshot> snapshot,
                               int chunkCount,
                               Optional<BlobGranuleCipherKeysCtx> cipherKeysCtx) {
	Standalone<IndexedBlobGranuleFile> file;

	file.init(cipherKeysCtx);
	ASSERT(file.indexBlock.present());

	size_t targetChunkBytes = snapshot.expectedSize() / chunkCount;
	size_t currentChunkBytesEstimate = 0;
	size_t previousChunkBytes = 0;

	std::vector<Value> chunks;
	chunks.push_back(Value()); // dummy value for index block
	Standalone<GranuleSnapshot> currentChunk;

	// fmt::print("Chunk index:\n");
	for (int i = 0; i < snapshot.size(); i++) {
		// TODO REMOVE sanity check
		if (i > 0) {
			ASSERT(snapshot[i - 1].key < snapshot[i].key);
		}

		currentChunk.push_back_deep(currentChunk.arena(), snapshot[i]);
		currentChunkBytesEstimate += snapshot[i].expectedSize();

		if (currentChunkBytesEstimate >= targetChunkBytes || i == snapshot.size() - 1) {
			// TODO: add encryption/compression for each chunk
			// TODO: protocol version
			Value serialized = ObjectWriter::toValue(currentChunk, Unversioned());

			TraceEvent("BeforeChunkCompress").log();
			serialized = file.compressChunkIfEnabled(serialized);
			TraceEvent("AfterChunkCompress").log();
			serialized = file.encryptChunkIfEnabled(cipherKeysCtx, serialized);
			TraceEvent("AfterChunkEncrypt").log();
			chunks.push_back(serialized);

			// TODO remove validation
			if (!file.indexBlock.get().children.empty()) {
				ASSERT(file.indexBlock.get().children.back().key < currentChunk.begin()->key);
			}
			file.indexBlock.get().children.emplace_back_deep(
			    file.arena(), currentChunk.begin()->key, previousChunkBytes);

			previousChunkBytes += serialized.size();
			currentChunkBytesEstimate = 0;
			currentChunk = Standalone<GranuleSnapshot>();
		}
	}
	ASSERT(currentChunk.empty());
	// push back dummy last chunk to get last chunk size, and to know last key in last block without having to read it
	if (!snapshot.empty()) {
		file.indexBlock.get().children.emplace_back_deep(
		    file.arena(), keyAfter(snapshot.back().key), previousChunkBytes);
	}

	Value indexBlock = serializeIndexBlock(file, cipherKeysCtx);
	// Ensure if encryption is enabled, then, indexBlock gets encrypted.
	ASSERT((file.encrypted.present() && !file.indexBlock.present()) ||
	       (!file.encrypted.present() && file.indexBlock.present()));

	int32_t indexSize = indexBlock.size();
	chunks[0] = indexBlock;

	// TODO: write this directly to stream to avoid extra copy?
	Arena ret;

	size_t size = indexSize + previousChunkBytes;
	uint8_t* buffer = new (ret) uint8_t[size];

	previousChunkBytes = 0;
	for (auto& it : chunks) {
		memcpy(buffer + previousChunkBytes, it.begin(), it.size());
		previousChunkBytes += it.size();
	}
	ASSERT(size == previousChunkBytes);

	return Standalone<StringRef>(StringRef(buffer, size), ret);
}

// TODO: use redwood prefix trick to optimize cpu comparison
static Arena loadSnapshotFile(const StringRef& snapshotData,
                              KeyRangeRef keyRange,
                              std::map<KeyRef, ValueRef>& dataMap,
                              Optional<BlobGranuleCipherKeysCtx> cipherKeysCtx) {
	Arena rootArena;

	Standalone<IndexedBlobGranuleFile> file = IndexedBlobGranuleFile::fromFileBytes(snapshotData, cipherKeysCtx);

	ASSERT(file.fileType == SNAPSHOT_FILE_TYPE);
	ASSERT(file.indexBlock.present());

	// empty snapshot file
	if (file.indexBlock.get().children.empty()) {
		return rootArena;
	}

	ASSERT(file.indexBlock.get().children.size() >= 2);

	// TODO: refactor this out of delta tree
	// int commonPrefixLen = commonPrefixLength(index.dataBlockOffsets.front().first,
	// index.dataBlockOffsets.back().first);

	// find range of blocks needed to read
	ChildBlockPointerRef* currentBlock = file.findStartBlock(keyRange.begin);

	// FIXME: optimize cpu comparisons here in first/last partial blocks, doing entire blocks at once based on
	// comparison, and using shared prefix for key comparison
	while (currentBlock != (file.indexBlock.get().children.end() - 1) && keyRange.end > currentBlock->key) {
		Standalone<GranuleSnapshot> dataBlock = file.getChild<GranuleSnapshot>(currentBlock, cipherKeysCtx);
		ASSERT(!dataBlock.empty());
		ASSERT(currentBlock->key == dataBlock.front().key);

		bool anyRows = false;
		for (auto& entry : dataBlock) {
			if (entry.key >= keyRange.begin && entry.key < keyRange.end) {
				dataMap.insert({ entry.key, entry.value });
				anyRows = true;
			}
		}
		if (anyRows) {
			rootArena.dependsOn(dataBlock.arena());
		}
		currentBlock++;
	}

	return rootArena;
}

static void applyDelta(KeyRangeRef keyRange, MutationRef m, std::map<KeyRef, ValueRef>& dataMap) {
	if (m.type == MutationRef::ClearRange) {
		if (m.param2 <= keyRange.begin || m.param1 >= keyRange.end) {
			return;
		}
		// keyRange is inclusive on start, lower_bound is inclusive with the argument, and erase is inclusive for the
		// begin. So if lower bound didn't find the exact key, we need to go up one so it doesn't erase an extra key
		// outside the range.
		std::map<KeyRef, ValueRef>::iterator itStart = dataMap.lower_bound(m.param1);
		if (itStart != dataMap.end() && itStart->first < m.param1) {
			itStart++;
		}

		// keyRange is exclusive on end, lower bound is inclusive with the argument, and erase is exclusive for the end
		// key. So if lower bound didn't find the exact key, we need to go up one so it doesn't skip the last key it
		// should erase
		std::map<KeyRef, ValueRef>::iterator itEnd = dataMap.lower_bound(m.param2);
		if (itEnd != dataMap.end() && itEnd->first < m.param2) {
			itEnd++;
		}
		dataMap.erase(itStart, itEnd);
	} else {
		// We don't need atomics here since eager reads handles it
		ASSERT(m.type == MutationRef::SetValue);
		if (m.param1 < keyRange.begin || m.param1 >= keyRange.end) {
			return;
		}

		std::map<KeyRef, ValueRef>::iterator it = dataMap.find(m.param1);
		if (it == dataMap.end()) {
			dataMap.insert({ m.param1, m.param2 });
		} else {
			it->second = m.param2;
		}
	}
}

static void applyDeltas(const GranuleDeltas& deltas,
                        KeyRangeRef keyRange,
                        Version beginVersion,
                        Version readVersion,
                        Version& lastFileEndVersion,
                        std::map<KeyRef, ValueRef>& dataMap) {
	if (deltas.empty()) {
		return;
	}
	// check that consecutive delta file versions are disjoint
	ASSERT(lastFileEndVersion < deltas.front().version);

	const MutationsAndVersionRef* mutationIt = deltas.begin();
	// prune beginVersion if necessary
	if (beginVersion > deltas.front().version) {
		ASSERT(beginVersion <= deltas.back().version);
		// binary search for beginVersion
		mutationIt = std::lower_bound(deltas.begin(),
		                              deltas.end(),
		                              MutationsAndVersionRef(beginVersion, 0),
		                              MutationsAndVersionRef::OrderByVersion());
	}

	while (mutationIt != deltas.end()) {
		if (mutationIt->version > readVersion) {
			lastFileEndVersion = readVersion;
			return;
		}
		for (auto& m : mutationIt->mutations) {
			applyDelta(keyRange, m, dataMap);
		}
		mutationIt++;
	}
	lastFileEndVersion = deltas.back().version;
}

static Arena loadDeltaFile(StringRef deltaData,
                           KeyRangeRef keyRange,
                           Version beginVersion,
                           Version readVersion,
                           Version& lastFileEndVersion,
                           std::map<KeyRef, ValueRef>& dataMap) {
	Arena parseArena;
	GranuleDeltas deltas;
	ObjectReader reader(deltaData.begin(), Unversioned());
	reader.deserialize(FileIdentifierFor<GranuleDeltas>::value, deltas, parseArena);

	if (BG_READ_DEBUG) {
		fmt::print("Parsed {} deltas from file\n", deltas.size());
	}

	// TODO REMOVE sanity check
	for (int i = 0; i < deltas.size() - 1; i++) {
		if (deltas[i].version > deltas[i + 1].version) {
			fmt::print(
			    "BG VERSION ORDER VIOLATION IN DELTA FILE: '{0}', '{1}'\n", deltas[i].version, deltas[i + 1].version);
		}
		ASSERT(deltas[i].version <= deltas[i + 1].version);
	}

	applyDeltas(deltas, keyRange, beginVersion, readVersion, lastFileEndVersion, dataMap);
	return parseArena;
}

RangeResult materializeBlobGranule(const BlobGranuleChunkRef& chunk,
                                   KeyRangeRef keyRange,
                                   Version beginVersion,
                                   Version readVersion,
                                   Optional<StringRef> snapshotData,
                                   StringRef deltaFileData[]) {
	// TODO REMOVE with early replying
	ASSERT(readVersion == chunk.includedVersion);

	// Arena to hold all allocations for applying deltas. Most of it, and the arenas produced by reading the files,
	// will likely be tossed if there are a significant number of mutations, so we copy at the end instead of doing a
	// dependsOn.
	// FIXME: probably some threshold of a small percentage of the data is actually changed, where it makes sense to
	// just to dependsOn instead of copy, to use a little extra memory footprint to help cpu?
	Arena arena;
	std::map<KeyRef, ValueRef> dataMap;
	Version lastFileEndVersion = invalidVersion;
	KeyRange requestRange;
	if (chunk.tenantPrefix.present()) {
		requestRange = keyRange.withPrefix(chunk.tenantPrefix.get());
	} else {
		requestRange = keyRange;
	}

	if (snapshotData.present()) {
		Arena snapshotArena = loadSnapshotFile(snapshotData.get(), requestRange, dataMap, chunk.cipherKeysCtx);
		arena.dependsOn(snapshotArena);
	}

	if (BG_READ_DEBUG) {
		fmt::print("Applying {} delta files\n", chunk.deltaFiles.size());
	}
	for (int deltaIdx = 0; deltaIdx < chunk.deltaFiles.size(); deltaIdx++) {
		Arena deltaArena = loadDeltaFile(
		    deltaFileData[deltaIdx], requestRange, beginVersion, readVersion, lastFileEndVersion, dataMap);
		arena.dependsOn(deltaArena);
	}
	if (BG_READ_DEBUG) {
		fmt::print("Applying {} memory deltas\n", chunk.newDeltas.size());
	}
	applyDeltas(chunk.newDeltas, requestRange, beginVersion, readVersion, lastFileEndVersion, dataMap);

	RangeResult ret;
	for (auto& it : dataMap) {
		ret.push_back_deep(
		    ret.arena(),
		    KeyValueRef(chunk.tenantPrefix.present() ? it.first.removePrefix(chunk.tenantPrefix.get()) : it.first,
		                it.second));
	}

	return ret;
}

struct GranuleLoadIds {
	Optional<int64_t> snapshotId;
	std::vector<int64_t> deltaIds;
};

static void startLoad(const ReadBlobGranuleContext granuleContext,
                      const BlobGranuleChunkRef& chunk,
                      GranuleLoadIds& loadIds) {

	// Start load process for all files in chunk
	if (chunk.snapshotFile.present()) {
		std::string snapshotFname = chunk.snapshotFile.get().filename.toString();
		// FIXME: remove when we implement file multiplexing
		ASSERT(chunk.snapshotFile.get().offset == 0);
		ASSERT(chunk.snapshotFile.get().length == chunk.snapshotFile.get().fullFileLength);
		loadIds.snapshotId = granuleContext.start_load_f(snapshotFname.c_str(),
		                                                 snapshotFname.size(),
		                                                 chunk.snapshotFile.get().offset,
		                                                 chunk.snapshotFile.get().length,
		                                                 chunk.snapshotFile.get().fullFileLength,
		                                                 granuleContext.userContext);
	}
	loadIds.deltaIds.reserve(chunk.deltaFiles.size());
	for (int deltaFileIdx = 0; deltaFileIdx < chunk.deltaFiles.size(); deltaFileIdx++) {
		std::string deltaFName = chunk.deltaFiles[deltaFileIdx].filename.toString();
		// FIXME: remove when we implement file multiplexing
		ASSERT(chunk.deltaFiles[deltaFileIdx].offset == 0);
		ASSERT(chunk.deltaFiles[deltaFileIdx].length == chunk.deltaFiles[deltaFileIdx].fullFileLength);
		int64_t deltaLoadId = granuleContext.start_load_f(deltaFName.c_str(),
		                                                  deltaFName.size(),
		                                                  chunk.deltaFiles[deltaFileIdx].offset,
		                                                  chunk.deltaFiles[deltaFileIdx].length,
		                                                  chunk.deltaFiles[deltaFileIdx].fullFileLength,
		                                                  granuleContext.userContext);
		loadIds.deltaIds.push_back(deltaLoadId);
	}
}

ErrorOr<RangeResult> loadAndMaterializeBlobGranules(const Standalone<VectorRef<BlobGranuleChunkRef>>& files,
                                                    const KeyRangeRef& keyRange,
                                                    Version beginVersion,
                                                    Version readVersion,
                                                    ReadBlobGranuleContext granuleContext) {
	int64_t parallelism = granuleContext.granuleParallelism;
	if (parallelism < 1) {
		parallelism = 1;
	}
	if (parallelism >= CLIENT_KNOBS->BG_MAX_GRANULE_PARALLELISM) {
		parallelism = CLIENT_KNOBS->BG_MAX_GRANULE_PARALLELISM;
	}

	GranuleLoadIds loadIds[files.size()];

	// Kick off first file reads if parallelism > 1
	for (int i = 0; i < parallelism - 1 && i < files.size(); i++) {
		startLoad(granuleContext, files[i], loadIds[i]);
	}

	try {
		RangeResult results;
		for (int chunkIdx = 0; chunkIdx < files.size(); chunkIdx++) {
			// Kick off files for this granule if parallelism == 1, or future granule if parallelism > 1
			if (chunkIdx + parallelism - 1 < files.size()) {
				startLoad(granuleContext, files[chunkIdx + parallelism - 1], loadIds[chunkIdx + parallelism - 1]);
			}

			RangeResult chunkRows;

			// once all loads kicked off, load data for chunk
			Optional<StringRef> snapshotData;
			if (files[chunkIdx].snapshotFile.present()) {
				snapshotData =
				    StringRef(granuleContext.get_load_f(loadIds[chunkIdx].snapshotId.get(), granuleContext.userContext),
				              files[chunkIdx].snapshotFile.get().length);
				if (!snapshotData.get().begin()) {
					return ErrorOr<RangeResult>(blob_granule_file_load_error());
				}
			}

			StringRef deltaData[files[chunkIdx].deltaFiles.size()];
			for (int i = 0; i < files[chunkIdx].deltaFiles.size(); i++) {
				deltaData[i] =
				    StringRef(granuleContext.get_load_f(loadIds[chunkIdx].deltaIds[i], granuleContext.userContext),
				              files[chunkIdx].deltaFiles[i].length);
				// null data is error
				if (!deltaData[i].begin()) {
					return ErrorOr<RangeResult>(blob_granule_file_load_error());
				}
			}

			// materialize rows from chunk
			chunkRows =
			    materializeBlobGranule(files[chunkIdx], keyRange, beginVersion, readVersion, snapshotData, deltaData);

			results.arena().dependsOn(chunkRows.arena());
			results.append(results.arena(), chunkRows.begin(), chunkRows.size());

			if (loadIds[chunkIdx].snapshotId.present()) {
				granuleContext.free_load_f(loadIds[chunkIdx].snapshotId.get(), granuleContext.userContext);
			}
			for (int i = 0; i < loadIds[chunkIdx].deltaIds.size(); i++) {
				granuleContext.free_load_f(loadIds[chunkIdx].deltaIds[i], granuleContext.userContext);
			}
		}
		return ErrorOr<RangeResult>(results);
	} catch (Error& e) {
		return ErrorOr<RangeResult>(e);
	}
}

std::string randomBGFilename(UID blobWorkerID, UID granuleID, Version version, std::string suffix) {
	// Start with random bytes to avoid metadata hotspotting
	// Worker ID for uniqueness and attribution
	// Granule ID for uniqueness and attribution
	// Version for uniqueness and possible future use
	return deterministicRandom()->randomUniqueID().shortString().substr(0, 8) + "_" +
	       blobWorkerID.shortString().substr(0, 8) + "_" + granuleID.shortString() + "_V" + std::to_string(version) +
	       suffix;
}

TEST_CASE("/blobgranule/files/applyDelta") {
	printf("Testing blob granule delta applying\n");
	Arena a;

	// do this 2 phase arena creation of string refs instead of LiteralStringRef because there is no char* StringRef
	// constructor, and valgrind might complain if the stringref data isn't in the arena
	std::string sk_a = "A";
	std::string sk_ab = "AB";
	std::string sk_b = "B";
	std::string sk_c = "C";
	std::string sk_z = "Z";
	std::string sval1 = "1";
	std::string sval2 = "2";

	StringRef k_a = StringRef(a, sk_a);
	StringRef k_ab = StringRef(a, sk_ab);
	StringRef k_b = StringRef(a, sk_b);
	StringRef k_c = StringRef(a, sk_c);
	StringRef k_z = StringRef(a, sk_z);
	StringRef val1 = StringRef(a, sval1);
	StringRef val2 = StringRef(a, sval2);

	std::map<KeyRef, ValueRef> data;
	data.insert({ k_a, val1 });
	data.insert({ k_ab, val1 });
	data.insert({ k_b, val1 });

	std::map<KeyRef, ValueRef> correctData = data;
	std::map<KeyRef, ValueRef> originalData = data;

	ASSERT(data == correctData);

	// test all clear permutations

	MutationRef mClearEverything(MutationRef::ClearRange, allKeys.begin, allKeys.end);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mClearEverything, data);
	correctData.clear();
	ASSERT(data == correctData);

	MutationRef mClearEverything2(MutationRef::ClearRange, allKeys.begin, k_c);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mClearEverything2, data);
	correctData.clear();
	ASSERT(data == correctData);

	MutationRef mClearEverything3(MutationRef::ClearRange, k_a, allKeys.end);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mClearEverything3, data);
	correctData.clear();
	ASSERT(data == correctData);

	MutationRef mClearEverything4(MutationRef::ClearRange, k_a, k_c);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mClearEverything, data);
	correctData.clear();
	ASSERT(data == correctData);

	MutationRef mClearFirst(MutationRef::ClearRange, k_a, k_ab);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mClearFirst, data);
	correctData.erase(k_a);
	ASSERT(data == correctData);

	MutationRef mClearSecond(MutationRef::ClearRange, k_ab, k_b);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mClearSecond, data);
	correctData.erase(k_ab);
	ASSERT(data == correctData);

	MutationRef mClearThird(MutationRef::ClearRange, k_b, k_c);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mClearThird, data);
	correctData.erase(k_b);
	ASSERT(data == correctData);

	MutationRef mClearFirst2(MutationRef::ClearRange, k_a, k_b);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mClearFirst2, data);
	correctData.erase(k_a);
	correctData.erase(k_ab);
	ASSERT(data == correctData);

	MutationRef mClearLast2(MutationRef::ClearRange, k_ab, k_c);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mClearLast2, data);
	correctData.erase(k_ab);
	correctData.erase(k_b);
	ASSERT(data == correctData);

	// test set data
	MutationRef mSetA(MutationRef::SetValue, k_a, val2);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mSetA, data);
	correctData[k_a] = val2;
	ASSERT(data == correctData);

	MutationRef mSetAB(MutationRef::SetValue, k_ab, val2);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mSetAB, data);
	correctData[k_ab] = val2;
	ASSERT(data == correctData);

	MutationRef mSetB(MutationRef::SetValue, k_b, val2);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mSetB, data);
	correctData[k_b] = val2;
	ASSERT(data == correctData);

	MutationRef mSetC(MutationRef::SetValue, k_c, val2);
	data = originalData;
	correctData = originalData;
	applyDelta(allKeys, mSetC, data);
	correctData[k_c] = val2;
	ASSERT(data == correctData);

	// test pruning deltas that are outside of the key range

	MutationRef mSetZ(MutationRef::SetValue, k_z, val2);
	data = originalData;
	applyDelta(KeyRangeRef(k_a, k_c), mSetZ, data);
	ASSERT(data == originalData);

	applyDelta(KeyRangeRef(k_ab, k_c), mSetA, data);
	ASSERT(data == originalData);

	applyDelta(KeyRangeRef(k_ab, k_c), mClearFirst, data);
	ASSERT(data == originalData);

	applyDelta(KeyRangeRef(k_a, k_ab), mClearThird, data);
	ASSERT(data == originalData);

	return Void();
}

// picks a number between 2^minExp and 2^maxExp, but uniformly distributed over exponential buckets 2^n an 2^n+1
int randomExp(int minExp, int maxExp) {
	if (minExp == maxExp) { // N=2, case
		return 1 << minExp;
	}
	int val = 1 << deterministicRandom()->randomInt(minExp, maxExp);
	ASSERT(val > 0);
	return deterministicRandom()->randomInt(val, val * 2);
}

void checkEmpty(const Value& serialized, Key begin, Key end, Optional<BlobGranuleCipherKeysCtx> cipherKeysCtx) {
	std::map<KeyRef, ValueRef> result;
	Arena ar = loadSnapshotFile(serialized, KeyRangeRef(begin, end), result, cipherKeysCtx);
	ASSERT(result.empty());
}

// endIdx is exclusive
void checkRead(const Standalone<GranuleSnapshot>& snapshot,
               const Value& serialized,
               int beginIdx,
               int endIdx,
               Optional<BlobGranuleCipherKeysCtx> cipherKeysCtx) {
	ASSERT(beginIdx < endIdx);
	ASSERT(endIdx <= snapshot.size());
	std::map<KeyRef, ValueRef> result;
	KeyRef beginKey = snapshot[beginIdx].key;
	Key endKey = endIdx == snapshot.size() ? keyAfter(snapshot.back().key) : snapshot[endIdx].key;
	KeyRangeRef range(beginKey, endKey);

	Arena ar = loadSnapshotFile(serialized, range, result, cipherKeysCtx);

	if (result.size() != endIdx - beginIdx) {
		fmt::print("Read {0} rows != {1}\n", result.size(), endIdx - beginIdx);
	}
	ASSERT(result.size() == endIdx - beginIdx);
	for (auto& it : result) {
		if (it.first != snapshot[beginIdx].key) {
			fmt::print("Key {0} != {1}\n", it.first.printable(), snapshot[beginIdx].key.printable());
		}
		ASSERT(it.first == snapshot[beginIdx].key);
		if (it.first != snapshot[beginIdx].key) {
			fmt::print("Value {0} != {1} for Key {2}\n",
			           it.second.printable(),
			           snapshot[beginIdx].value.printable(),
			           it.first.printable());
		}
		ASSERT(it.second == snapshot[beginIdx].value);
		beginIdx++;
	}
}

namespace {
const EncryptCipherDomainId encryptDomainId = deterministicRandom()->randomInt(1, 20);
const EncryptCipherBaseKeyId encryptBaseCipherId = deterministicRandom()->randomInt(15, 100);
const EncryptCipherRandomSalt encryptSalt = deterministicRandom()->randomInt(12345, 78600);

Standalone<StringRef> getBaseCipher() {
	Standalone<StringRef> baseCipher = makeString(AES_256_KEY_LENGTH);
	generateRandomData(mutateString(baseCipher), baseCipher.size());
	return baseCipher;
}

Standalone<StringRef> encryptBaseCipher = getBaseCipher();

BlobGranuleCipherKeysCtx getCipherKeysCtx(Arena& arena) {
	BlobGranuleCipherKeysCtx cipherKeysCtx;

	cipherKeysCtx.textCipherKey.cipherDetails = BlobCipherDetails(encryptDomainId, encryptBaseCipherId, encryptSalt);
	cipherKeysCtx.textCipherKey.baseCipher = StringRef(arena, encryptBaseCipher);
	cipherKeysCtx.headerCipherKey.cipherDetails =
	    BlobCipherDetails(SYSTEM_KEYSPACE_ENCRYPT_DOMAIN_ID, encryptBaseCipherId, encryptSalt);
	cipherKeysCtx.headerCipherKey.baseCipher = StringRef(arena, encryptBaseCipher);

	cipherKeysCtx.ivRef = makeString(AES_256_IV_LENGTH);
	generateRandomData(mutateString(cipherKeysCtx.ivRef), AES_256_IV_LENGTH);

	return cipherKeysCtx;
}
} // namespace

TEST_CASE("/blobgranule/files/snapshotFormatUnitTest") {
	// snapshot files are likely to have a non-trivial shared prefix since they're for a small contiguous key range
	std::string sharedPrefix = deterministicRandom()->randomUniqueID().toString();
	int uidSize = sharedPrefix.size();
	int sharedPrefixLen = deterministicRandom()->randomInt(0, uidSize);
	int targetKeyLength = deterministicRandom()->randomInt(4, uidSize);
	sharedPrefix = sharedPrefix.substr(0, sharedPrefixLen) + "_";

	int targetValueLen = randomExp(0, 12);
	int targetChunks = randomExp(0, 9);
	int targetDataBytes = randomExp(0, 25);

	std::unordered_set<std::string> usedKeys;
	Standalone<GranuleSnapshot> data;
	int totalDataBytes = 0;
	while (totalDataBytes < targetDataBytes) {
		int keySize = deterministicRandom()->randomInt(targetKeyLength / 2, targetKeyLength * 3 / 2);
		keySize = std::min(keySize, uidSize);
		std::string key = sharedPrefix + deterministicRandom()->randomUniqueID().toString().substr(0, keySize);
		if (usedKeys.insert(key).second) {
			int valueSize = deterministicRandom()->randomInt(targetValueLen / 2, targetValueLen * 3 / 2);
			std::string value = deterministicRandom()->randomUniqueID().toString();
			if (value.size() > valueSize) {
				value = value.substr(0, valueSize);
			}
			if (value.size() < valueSize) {
				value += std::string(valueSize - value.size(), 'x');
			}

			data.push_back_deep(data.arena(), KeyValueRef(KeyRef(key), ValueRef(value)));
			totalDataBytes += key.size() + value.size();
		}
	}

	std::sort(data.begin(), data.end(), KeyValueRef::OrderByKey());

	int maxExp = 0;
	while (1 << maxExp < data.size()) {
		maxExp++;
	}
	maxExp--;

	fmt::print("Validating snapshot data is sorted\n");
	for (int i = 0; i < data.size() - 1; i++) {
		ASSERT(data[i].key < data[i + 1].key);
	}

	fmt::print(
	    "Constructing snapshot with {0} rows, {1} bytes, and {2} chunks\n", data.size(), totalDataBytes, targetChunks);

	Optional<BlobGranuleCipherKeysCtx> cipherKeysCtx;
	Arena arena;
	// if (1) { // deterministicRandom()->coinflip()) {
	cipherKeysCtx = getCipherKeysCtx(arena);
	//} else {
	// cipherKeysCtx.reset();
	//}
	Value serialized = serializeChunkedSnapshot(data, targetChunks, cipherKeysCtx);

	fmt::print("Snapshot serialized! {0} bytes\n", serialized.size());

	fmt::print("Validating snapshot data is sorted again\n");
	for (int i = 0; i < data.size() - 1; i++) {
		ASSERT(data[i].key < data[i + 1].key);
	}

	fmt::print("Initial read starting\n");

	checkRead(data, serialized, 0, data.size(), cipherKeysCtx);

	fmt::print("Initial read complete\n");

	if (data.size() > 1) {
		for (int i = 0; i < std::min(100, data.size() * 2); i++) {
			int width = randomExp(0, maxExp);
			ASSERT(width <= data.size());
			int start = deterministicRandom()->randomInt(0, data.size() - width);
			checkRead(data, serialized, start, start + width, cipherKeysCtx);
		}

		fmt::print("Doing empty checks\n");
		int randomIdx = deterministicRandom()->randomInt(0, data.size() - 1);
		checkEmpty(serialized, keyAfter(data[randomIdx].key), data[randomIdx + 1].key, cipherKeysCtx);
	} else {
		fmt::print("Doing empty checks\n");
	}

	checkEmpty(serialized, normalKeys.begin, data.front().key, cipherKeysCtx);
	checkEmpty(serialized, normalKeys.begin, LiteralStringRef("\x00"), cipherKeysCtx);
	checkEmpty(serialized, keyAfter(data.back().key), normalKeys.end, cipherKeysCtx);
	checkEmpty(serialized, LiteralStringRef("\xfe"), normalKeys.end, cipherKeysCtx);

	fmt::print("Snapshot format test done!\n");

	return Void();
}