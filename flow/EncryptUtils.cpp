/*
 * EncryptUtils.cpp
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

#include "flow/EncryptUtils.h"
#include "flow/Trace.h"

#include <boost/format.hpp>

EncryptCipherMode encryptModeFromString(const std::string& modeStr) {
	if (modeStr == "NONE") {
		return ENCRYPT_CIPHER_MODE_NONE;
	} else if (modeStr == "AES-256-CTR") {
		return ENCRYPT_CIPHER_MODE_AES_256_CTR;
	} else {
		TraceEvent("EncryptModeFromString").log();
		throw not_implemented();
	}
}

std::string getEncryptDbgTraceKey(std::string_view prefix,
                                  EncryptCipherDomainId domainId,
                                  StringRef domainName,
                                  Optional<EncryptCipherBaseKeyId> baseCipherId) {
	// Construct the TraceEvent field key ensuring its uniqueness and compliance to TraceEvent field validator and log
	// parsing tools
	if (baseCipherId.present()) {
		boost::format fmter("%s.%lld.%s.%llu");
		return boost::str(boost::format(fmter % prefix % domainId % domainName.toString() % baseCipherId.get()));
	} else {
		boost::format fmter("%s.%lld.%s");
		return boost::str(boost::format(fmter % prefix % domainId % domainName.toString()));
	}
}

std::string getEncryptDbgTraceKeyWithTS(std::string_view prefix,
                                        EncryptCipherDomainId domainId,
                                        StringRef domainName,
                                        EncryptCipherBaseKeyId baseCipherId,
                                        int64_t refAfterTS,
                                        int64_t expAfterTS) {
	// Construct the TraceEvent field key ensuring its uniqueness and compliance to TraceEvent field validator and log
	// parsing tools
	boost::format fmter("%s.%lld.%s.%llu.%lld.%lld");
	return boost::str(
	    boost::format(fmter % prefix % domainId % domainName.toString() % baseCipherId % refAfterTS % expAfterTS));
}
