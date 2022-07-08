/*
 * GZipUtils.cpp
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
#include "flow/IRandom.h"
#include "flow/UnitTest.h"

#include <boost/iostreams/filter/zlib.hpp>
#include <sstream>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/zstd.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>

StringRef CompressionUtils::compress(const CompressionFilter filter, StringRef data, Arena& arena) {
	if (filter == CompressionFilter::NONE) {
		return StringRef(arena, data);
	}

	namespace bio = boost::iostreams;
	if (filter == CompressionFilter::GZIP) {
		return CompressionUtils::compress(filter, data, bio::gzip::default_compression, arena);
	} else if (filter == CompressionFilter::ZSTD) {
		return CompressionUtils::compress(filter, data, bio::zstd::default_compression, arena);
	} else {
		throw not_implemented();
	}
}

StringRef CompressionUtils::compress(const CompressionFilter filter, StringRef data, int level, Arena& arena) {
	if (filter == CompressionFilter::NONE) {
		return StringRef(arena, data);
	}

	// FIXME: Remove after resolving compilation issues
	return StringRef(arena, data);

	/*
	namespace bio = boost::iostreams;
	std::stringstream compStream;
	std::stringstream decomStream(data.toString());

	bio::filtering_streambuf<bio::input> out;
	if (type == CompressionFilter::GZIP) {
	    out.push(bio::gzip_compressor(bio::gzip_params(level)));
	} else if (type == CompressionFilter::ZSTD) {
	    out.push(bio::zstd_compressor(bio::zstd_params(level)));
	} else {
	    throw not_implemented();
	}
	out.push(decomStream);
	bio::copy(out, compStream);

	return StringRef(arena, compStream.str());
	*/
}

StringRef CompressionUtils::decompress(const CompressionFilter filter, StringRef data, Arena& arena) {
	if (filter == CompressionFilter::NONE) {
		return StringRef(arena, data);
	}

	// FIXME: Remove after resolving compilation issues
	return StringRef(arena, data);

	/*
	namespace bio = boost::iostreams;
	std::stringstream compStream(data.toString());
	std::stringstream decompStream;

	bio::filtering_streambuf<bio::input> out;
	if (type == CompressionFilter::GZIP) {
	    out.push(bio::gzip_decompressor());
	} else if (type == CompressionFilter::ZSTD) {
	    out.push(bio::zstd_decompressor());
	} else {
	    throw not_implemented();
	}
	out.push(compStream);
	bio::copy(out, decompStream);

	return StringRef(arena, decompStream.str());
	*/
}

TEST_CASE("flow/CompressionUtils/noCompression") {
	Arena arena;
	const int size = deterministicRandom()->randomInt(512, 1024);
	Standalone<StringRef> uncompressed = makeString(size);
	generateRandomData(mutateString(uncompressed), size);

	Standalone<StringRef> compressed = CompressionUtils::compress(CompressionFilter::NONE, uncompressed, arena);
	ASSERT_EQ(compressed.compare(uncompressed), 0);

	StringRef verify = CompressionUtils::decompress(CompressionFilter::NONE, compressed, arena);
	ASSERT_EQ(verify.compare(uncompressed), 0);

	return Void();
}

TEST_CASE("flow/CompressionUtils/zstdCompression") {
	Arena arena;
	const int size = deterministicRandom()->randomInt(512, 1024);
	Standalone<StringRef> uncompressed = makeString(size);
	generateRandomData(mutateString(uncompressed), size);

	Standalone<StringRef> compressed = CompressionUtils::compress(CompressionFilter::ZSTD, uncompressed, arena);
	ASSERT_EQ(compressed.compare(uncompressed), 0);

	StringRef verify = CompressionUtils::decompress(CompressionFilter::ZSTD, compressed, arena);
	ASSERT_EQ(verify.compare(uncompressed), 0);

	return Void();
}

TEST_CASE("flow/CompressionUtils/gzipCompression") {
	Arena arena;
	const int size = deterministicRandom()->randomInt(512, 1024);
	Standalone<StringRef> uncompressed = makeString(size);
	generateRandomData(mutateString(uncompressed), size);

	Standalone<StringRef> compressed = CompressionUtils::compress(CompressionFilter::GZIP, uncompressed, arena);
	ASSERT_EQ(compressed.compare(uncompressed), 0);

	StringRef verify = CompressionUtils::decompress(CompressionFilter::GZIP, compressed, arena);
	ASSERT_EQ(verify.compare(uncompressed), 0);

	return Void();
}