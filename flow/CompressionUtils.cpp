/*
 * CompressionUtils.cpp
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

#include "flow/CompressionUtils.h"

#include "flow/Arena.h"
#include "flow/Error.h"
#include "flow/IRandom.h"
#include "flow/UnitTest.h"

#include <boost/iostreams/copy.hpp>
#ifdef ZLIB_LIB_SUPPORTED
#include <boost/iostreams/filter/gzip.hpp>
#endif
#include <boost/iostreams/filtering_streambuf.hpp>
#ifdef ZSTD_LIB_SUPPORTED
#include <boost/iostreams/filter/zstd.hpp>
#endif
#include <sstream>

namespace {
std::unordered_set<CompressionFilter> getSupportedFilters() {
	std::unordered_set<CompressionFilter> filters;

	filters.insert(CompressionFilter::NONE);
#ifdef ZLIB_LIB_SUPPORTED
	filters.insert(CompressionFilter::GZIP);
#endif
#ifdef ZSTD_LIB_SUPPORTED
	filters.insert(CompressionFilter::ZSTD);
#endif
	ASSERT_GE(filters.size(), 1);
	return filters;
}
} // namespace

std::unordered_set<CompressionFilter> CompressionUtils::supportedFilters = getSupportedFilters();

StringRef CompressionUtils::compress(const CompressionFilter filter, const StringRef& data, Arena& arena) {
	checkFilterSupported(filter);

	if (filter == CompressionFilter::NONE) {
		return StringRef(arena, data);
	}

	namespace bio = boost::iostreams;
#ifdef ZLIB_LIB_SUPPORTED
	if (filter == CompressionFilter::GZIP) {
		return CompressionUtils::compress(filter, data, bio::gzip::default_compression, arena);
	}
#endif
#ifdef ZSTD_LIB_SUPPORTED
	if (filter == CompressionFilter::ZSTD) {
		return CompressionUtils::compress(filter, data, bio::zstd::default_compression, arena);
	}
#endif

	throw internal_error(); // We should never get here
}

StringRef CompressionUtils::compress(const CompressionFilter filter, const StringRef& data, int level, Arena& arena) {
	checkFilterSupported(filter);

	if (filter == CompressionFilter::NONE) {
		return StringRef(arena, data);
	}

	namespace bio = boost::iostreams;
	std::stringstream compStream;
	std::stringstream decomStream(data.toString());

	bio::filtering_streambuf<bio::input> out;
#ifdef ZLIB_LIB_SUPPORTED
	if (filter == CompressionFilter::GZIP) {
		out.push(bio::gzip_compressor(bio::gzip_params(level)));
	}
#endif
#ifdef ZSTD_LIB_SUPPORTED
	if (filter == CompressionFilter::ZSTD) {
		out.push(bio::zstd_compressor(bio::zstd_params(level)));
	}
#endif

	out.push(decomStream);
	bio::copy(out, compStream);

	return StringRef(arena, compStream.str());
}

StringRef CompressionUtils::decompress(const CompressionFilter filter, const StringRef& data, Arena& arena) {
	checkFilterSupported(filter);

	if (filter == CompressionFilter::NONE) {
		return StringRef(arena, data);
	}

	namespace bio = boost::iostreams;
	std::stringstream compStream(data.toString());
	std::stringstream decompStream;

	bio::filtering_streambuf<bio::input> out;
#ifdef ZLIB_LIB_SUPPORTED
	if (filter == CompressionFilter::GZIP) {
		out.push(bio::gzip_decompressor());
	}
#endif
#ifdef ZSTD_LIB_SUPPORTED
	if (filter == CompressionFilter::ZSTD) {
		out.push(bio::zstd_decompressor());
	}
#endif

	out.push(compStream);
	bio::copy(out, decompStream);

	return StringRef(arena, decompStream.str());
}

int CompressionUtils::getDefaultCompressionLevel(CompressionFilter filter) {
	checkFilterSupported(filter);

	if (filter == CompressionFilter::NONE) {
		return -1;
	}

#ifdef ZLIB_LIB_SUPPORTED
	if (filter == CompressionFilter::GZIP) {
		// opt for high speed compression, larger levels have a high cpu cost and not much compression ratio
		// improvement, according to benchmarks
		// return boost::iostream::gzip::default_compression;
		// return boost::iostream::gzip::best_compression;
		return boost::iostreams::gzip::best_speed;
	}
#endif
#ifdef ZSTD_LIB_SUPPORTED
	if (filter == CompressionFilter::ZSTD) {
		// opt for high speed compression, larger levels have a high cpu cost and not much compression ratio
		// improvement, according to benchmarks
		// return boost::iostreams::zstd::default_compression;
		// return boost::iostreams::zstd::best_compression;
		return boost::iostreams::zstd::best_speed;
	}
#endif

	throw internal_error(); // We should never get here
}

// Only used to link unit tests
void forceLinkCompressionUtilsTest() {}

namespace {
void testCompression(CompressionFilter filter) {
	Arena arena;
	const int size = deterministicRandom()->randomInt(512, 1024);
	Standalone<StringRef> uncompressed = makeString(size);
	deterministicRandom()->randomBytes(mutateString(uncompressed), size);

	Standalone<StringRef> compressed = CompressionUtils::compress(filter, uncompressed, arena);
	ASSERT_NE(compressed.compare(uncompressed), 0);

	StringRef verify = CompressionUtils::decompress(filter, compressed, arena);
	ASSERT_EQ(verify.compare(uncompressed), 0);
}

void testCompression2(CompressionFilter filter) {
	Arena arena;
	const int size = deterministicRandom()->randomInt(512, 1024);
	std::string s(size, 'x');
	Standalone<StringRef> uncompressed = Standalone<StringRef>(StringRef(s));
	printf("Size before: %d\n", (int)uncompressed.size());

	Standalone<StringRef> compressed = CompressionUtils::compress(filter, uncompressed, arena);
	ASSERT_NE(compressed.compare(uncompressed), 0);
	printf("Size after: %d\n", (int)compressed.size());
	// Assert compressed size is less than half.
	ASSERT(compressed.size() * 2 < uncompressed.size());

	StringRef verify = CompressionUtils::decompress(filter, compressed, arena);
	ASSERT_EQ(verify.compare(uncompressed), 0);
}

} // namespace

TEST_CASE("/CompressionUtils/noCompression") {
	Arena arena;
	const int size = deterministicRandom()->randomInt(512, 1024);
	Standalone<StringRef> uncompressed = makeString(size);
	deterministicRandom()->randomBytes(mutateString(uncompressed), size);

	Standalone<StringRef> compressed = CompressionUtils::compress(CompressionFilter::NONE, uncompressed, arena);
	ASSERT_EQ(compressed.compare(uncompressed), 0);

	StringRef verify = CompressionUtils::decompress(CompressionFilter::NONE, compressed, arena);
	ASSERT_EQ(verify.compare(uncompressed), 0);

	TraceEvent("NoCompressionDone");

	return Void();
}

#ifdef ZLIB_LIB_SUPPORTED
TEST_CASE("/CompressionUtils/gzipCompression") {
	testCompression(CompressionFilter::GZIP);
	TraceEvent("GzipCompressionDone");

	return Void();
}

TEST_CASE("/CompressionUtils/gzipCompression2") {
	testCompression2(CompressionFilter::GZIP);
	TraceEvent("GzipCompression2Done");

	return Void();
}
#endif

#ifdef ZSTD_LIB_SUPPORTED
TEST_CASE("/CompressionUtils/zstdCompression") {
	testCompression(CompressionFilter::ZSTD);
	TraceEvent("ZstdCompressionDone");

	return Void();
}

TEST_CASE("/CompressionUtils/zstdCompression2") {
	testCompression2(CompressionFilter::ZSTD);
	TraceEvent("ZstdCompression2Done");

	return Void();
}
#endif
