/*
 * RESTSimKmsVault.h
 *
 * This source file is part of the FoundationDB open source project
 *
 * Copyright 2013-2023 Apple Inc. and the FoundationDB project authors
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

#ifndef FDBSERVER_REST_SIM_KMS_VAULT_H
#define FDBSERVER_REST_SIM_KMS_VAULT_H
#pragma once

#include "fdbrpc/HTTP.h"
#include "fdbrpc/simulator.h"

namespace RestSimKms {

const std::string REST_SIM_KMS_HOSTNAME = "restsimkms";
const std::string REST_SIM_KMS_SERVICE_PORT = "7860";

const std::string REST_SIM_KMS_VAULT_DISCOVERY_FILE = "simfdb/restSimKmsDiscovery_urls";
const std::string REST_SIM_KMS_VAULT_TOKEN_NAME = "simKmsValidationToken";
const std::string REST_SIM_KMS_VAULT_TOKEN_FILE = "simfdb/restSimKmsValidation_tokens";

const std::string REST_SIM_KMS_VAULT_GET_ENCRYPTION_KEYS_BY_KEY_IDS_RESOURCE = "/get-encryption-keys-by-key-ids";
const std::string REST_SIM_KMS_VAULT_GET_ENCRYPTION_KEYS_BY_DOMAIN_IDS_RESOURCE = "/get-encryption-keys-by-domain-ids";
const std::string REST_SIM_KMS_VAULT_GET_BLOB_METADATA_RESOURCE = "/get-blob-metadata";

struct VaultRequestHandler : HTTP::IRequestHandler, ReferenceCounted<VaultRequestHandler> {
	Future<Void> handleRequest(Reference<HTTP::IncomingRequest> req,
	                           Reference<HTTP::OutgoingResponse> response) override;
	Reference<HTTP::IRequestHandler> clone() override { return makeReference<VaultRequestHandler>(); }

	void addref() override { ReferenceCounted<VaultRequestHandler>::addref(); }
	void delref() override { ReferenceCounted<VaultRequestHandler>::delref(); }
};

void cleanupConfig();
void initConfig();
void initDiscoverUrlFile();

} // namespace RestSimKms

#endif