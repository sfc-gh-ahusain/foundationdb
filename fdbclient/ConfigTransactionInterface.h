/*
 * ConfigTransactionInterface.h
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

#pragma once

#include "fdbclient/FDBTypes.h"
#include "fdbclient/CommitTransaction.h"
#include "fdbclient/ConfigKnobs.h"
#include "fdbclient/CoordinationInterface.h"
#include "fdbrpc/fdbrpc.h"
#include "flow/flow.h"

struct ConfigGeneration {
	// The live version of each node is monotonically increasing
	Version liveVersion{ 0 };
	// The committedVersion of each node is the version of the last commit made durable.
	// Each committedVersion was previously given to clients as a liveVersion, prior to commit.
	Version committedVersion{ 0 };

	bool operator==(ConfigGeneration const&) const;
	bool operator!=(ConfigGeneration const&) const;

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, liveVersion, committedVersion);
	}
};

struct ConfigTransactionGetGenerationReply {
	static constexpr FileIdentifier file_identifier = 2934851;
	ConfigTransactionGetGenerationReply() = default;
	explicit ConfigTransactionGetGenerationReply(ConfigGeneration generation) : generation(generation) {}
	ConfigGeneration generation;

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, generation);
	}
};

struct ConfigTransactionGetGenerationRequest {
	static constexpr FileIdentifier file_identifier = 138941;
	ReplyPromise<ConfigTransactionGetGenerationReply> reply;
	ConfigTransactionGetGenerationRequest() = default;

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, reply);
	}
};

struct ConfigTransactionGetReply {
	static constexpr FileIdentifier file_identifier = 2034110;
	Optional<KnobValue> value;
	ConfigTransactionGetReply() = default;
	explicit ConfigTransactionGetReply(Optional<KnobValue> const& value) : value(value) {}

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, value);
	}
};

struct ConfigTransactionGetRequest {
	static constexpr FileIdentifier file_identifier = 923040;
	ConfigGeneration generation;
	ConfigKey key;
	ReplyPromise<ConfigTransactionGetReply> reply;

	ConfigTransactionGetRequest() = default;
	explicit ConfigTransactionGetRequest(ConfigGeneration generation, ConfigKey key)
	  : generation(generation), key(key) {}

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, generation, key, reply);
	}
};

struct ConfigTransactionCommitRequest {
	static constexpr FileIdentifier file_identifier = 103841;
	Arena arena;
	ConfigGeneration generation{ ::invalidVersion, ::invalidVersion };
	VectorRef<ConfigMutationRef> mutations;
	ConfigCommitAnnotationRef annotation;
	ReplyPromise<Void> reply;

	size_t expectedSize() const { return mutations.expectedSize() + annotation.expectedSize(); }

	void set(KeyRef key, ValueRef value);
	void clear(KeyRef key);

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, arena, generation, mutations, annotation, reply);
	}
};

struct ConfigTransactionGetConfigClassesReply {
	static constexpr FileIdentifier file_identifier = 5309618;
	Standalone<VectorRef<KeyRef>> configClasses;

	ConfigTransactionGetConfigClassesReply() = default;
	explicit ConfigTransactionGetConfigClassesReply(Standalone<VectorRef<KeyRef>> const& configClasses)
	  : configClasses(configClasses) {}

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, configClasses);
	}
};

struct ConfigTransactionGetConfigClassesRequest {
	static constexpr FileIdentifier file_identifier = 7163400;
	ConfigGeneration generation;
	ReplyPromise<ConfigTransactionGetConfigClassesReply> reply;

	ConfigTransactionGetConfigClassesRequest() = default;
	explicit ConfigTransactionGetConfigClassesRequest(ConfigGeneration generation) : generation(generation) {}

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, generation);
	}
};

struct ConfigTransactionGetKnobsReply {
	static constexpr FileIdentifier file_identifier = 4109852;
	Standalone<VectorRef<KeyRef>> knobNames;

	ConfigTransactionGetKnobsReply() = default;
	explicit ConfigTransactionGetKnobsReply(Standalone<VectorRef<KeyRef>> const& knobNames) : knobNames(knobNames) {}

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, knobNames);
	}
};

struct ConfigTransactionGetKnobsRequest {
	static constexpr FileIdentifier file_identifier = 987410;
	ConfigGeneration generation;
	Optional<Key> configClass;
	ReplyPromise<ConfigTransactionGetKnobsReply> reply;

	ConfigTransactionGetKnobsRequest() = default;
	explicit ConfigTransactionGetKnobsRequest(ConfigGeneration generation, Optional<Key> configClass)
	  : generation(generation), configClass(configClass) {}

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, generation, configClass, reply);
	}
};

/*
 * Configuration database nodes serve a ConfigTransactionInterface which contains well known endpoints,
 * used by clients to transactionally update the configuration database
 */
struct ConfigTransactionInterface {
	UID _id;

public:
	static constexpr FileIdentifier file_identifier = 982485;
	struct RequestStream<ConfigTransactionGetGenerationRequest> getGeneration;
	struct RequestStream<ConfigTransactionGetRequest> get;
	struct RequestStream<ConfigTransactionGetConfigClassesRequest> getClasses;
	struct RequestStream<ConfigTransactionGetKnobsRequest> getKnobs;
	struct RequestStream<ConfigTransactionCommitRequest> commit;

	ConfigTransactionInterface();
	void setupWellKnownEndpoints();
	ConfigTransactionInterface(NetworkAddress const& remote);

	bool operator==(ConfigTransactionInterface const& rhs) const;
	bool operator!=(ConfigTransactionInterface const& rhs) const;
	UID id() const { return _id; }

	template <class Ar>
	void serialize(Ar& ar) {
		serializer(ar, getGeneration, get, getClasses, getKnobs, commit);
	}
};
