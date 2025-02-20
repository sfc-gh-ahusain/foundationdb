/*
 * fdbcli.actor.cpp
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

#include "boost/lexical_cast.hpp"
#include "fdbclient/NativeAPI.actor.h"
#include "fdbclient/FDBTypes.h"
#include "fdbclient/IClientApi.h"
#include "fdbclient/MultiVersionTransaction.h"
#include "fdbclient/Status.h"
#include "fdbclient/KeyBackedTypes.h"
#include "fdbclient/StatusClient.h"
#include "fdbclient/DatabaseContext.h"
#include "fdbclient/GlobalConfig.actor.h"
#include "fdbclient/IKnobCollection.h"
#include "fdbclient/NativeAPI.actor.h"
#include "fdbclient/ReadYourWrites.h"
#include "fdbclient/ClusterInterface.h"
#include "fdbclient/ManagementAPI.actor.h"
#include "fdbclient/Schemas.h"
#include "fdbclient/CoordinationInterface.h"
#include "fdbclient/FDBOptions.g.h"
#include "fdbclient/TagThrottle.h"
#include "fdbclient/Tuple.h"

#include "fdbclient/ThreadSafeTransaction.h"
#include "flow/DeterministicRandom.h"
#include "flow/Platform.h"

#include "flow/TLSConfig.actor.h"
#include "flow/SimpleOpt.h"

#include "fdbcli/FlowLineNoise.h"
#include "fdbcli/fdbcli.actor.h"

#include <cinttypes>
#include <type_traits>
#include <signal.h>

#ifdef __unixish__
#include <stdio.h>
#include "fdbcli/linenoise/linenoise.h"
#endif

#include "fdbclient/versions.h"
#include "fdbclient/BuildFlags.h"

#include "flow/actorcompiler.h" // This must be the last #include.

#define FDB_API_VERSION 710
/*
 * While we could just use the MultiVersionApi instance directly, this #define allows us to swap in any other IClientApi
 * instance (e.g. from ThreadSafeApi)
 */
#define API ((IClientApi*)MultiVersionApi::api)

extern const char* getSourceVersion();

std::vector<std::string> validOptions;

enum {
	OPT_CONNFILE,
	OPT_DATABASE,
	OPT_HELP,
	OPT_TRACE,
	OPT_TRACE_DIR,
	OPT_TIMEOUT,
	OPT_EXEC,
	OPT_NO_STATUS,
	OPT_NO_HINTS,
	OPT_STATUS_FROM_JSON,
	OPT_VERSION,
	OPT_BUILD_FLAGS,
	OPT_TRACE_FORMAT,
	OPT_KNOB,
	OPT_DEBUG_TLS
};

CSimpleOpt::SOption g_rgOptions[] = { { OPT_CONNFILE, "-C", SO_REQ_SEP },
	                                  { OPT_CONNFILE, "--cluster_file", SO_REQ_SEP },
	                                  { OPT_DATABASE, "-d", SO_REQ_SEP },
	                                  { OPT_TRACE, "--log", SO_NONE },
	                                  { OPT_TRACE_DIR, "--log-dir", SO_REQ_SEP },
	                                  { OPT_TIMEOUT, "--timeout", SO_REQ_SEP },
	                                  { OPT_EXEC, "--exec", SO_REQ_SEP },
	                                  { OPT_NO_STATUS, "--no-status", SO_NONE },
	                                  { OPT_NO_HINTS, "--no-hints", SO_NONE },
	                                  { OPT_HELP, "-?", SO_NONE },
	                                  { OPT_HELP, "-h", SO_NONE },
	                                  { OPT_HELP, "--help", SO_NONE },
	                                  { OPT_STATUS_FROM_JSON, "--status-from-json", SO_REQ_SEP },
	                                  { OPT_VERSION, "--version", SO_NONE },
	                                  { OPT_VERSION, "-v", SO_NONE },
	                                  { OPT_BUILD_FLAGS, "--build_flags", SO_NONE },
	                                  { OPT_TRACE_FORMAT, "--trace_format", SO_REQ_SEP },
	                                  { OPT_KNOB, "--knob_", SO_REQ_SEP },
	                                  { OPT_DEBUG_TLS, "--debug-tls", SO_NONE },

#ifndef TLS_DISABLED
	                                  TLS_OPTION_FLAGS
#endif

	                                      SO_END_OF_OPTIONS };

void printAtCol(const char* text, int col) {
	const char* iter = text;
	const char* start = text;
	const char* space = nullptr;

	do {
		iter++;
		if (*iter == '\n' || *iter == ' ' || *iter == '\0')
			space = iter;
		if (*iter == '\n' || *iter == '\0' || (iter - start == col)) {
			if (!space)
				space = iter;
			printf("%.*s\n", (int)(space - start), start);
			start = space;
			if (*start == ' ' || *start == '\n')
				start++;
			space = nullptr;
		}
	} while (*iter);
}

std::string lineWrap(const char* text, int col) {
	const char* iter = text;
	const char* start = text;
	const char* space = nullptr;
	std::string out = "";
	do {
		iter++;
		if (*iter == '\n' || *iter == ' ' || *iter == '\0')
			space = iter;
		if (*iter == '\n' || *iter == '\0' || (iter - start == col)) {
			if (!space)
				space = iter;
			out += format("%.*s\n", (int)(space - start), start);
			start = space;
			if (*start == ' ' /* || *start == '\n'*/)
				start++;
			space = nullptr;
		}
	} while (*iter);
	return out;
}

class FdbOptions {
public:
	// Prints an error and throws invalid_option or invalid_option_value if the option could not be set
	void setOption(Reference<ReadYourWritesTransaction> tr,
	               StringRef optionStr,
	               bool enabled,
	               Optional<StringRef> arg,
	               bool intrans) {
		auto transactionItr = transactionOptions.legalOptions.find(optionStr.toString());
		if (transactionItr != transactionOptions.legalOptions.end())
			setTransactionOption(tr, transactionItr->second, enabled, arg, intrans);
		else {
			fprintf(stderr,
			        "ERROR: invalid option '%s'. Try `help options' for a list of available options.\n",
			        optionStr.toString().c_str());
			throw invalid_option();
		}
	}

	// Applies all enabled transaction options to the given transaction
	void apply(Reference<ReadYourWritesTransaction> tr) {
		for (const auto& [name, value] : transactionOptions.options) {
			tr->setOption(name, value.castTo<StringRef>());
		}
	}

	// TODO: replace the above function after we refactor all fdbcli code
	void apply(Reference<ITransaction> tr) {
		for (const auto& [name, value] : transactionOptions.options) {
			tr->setOption(name, value.castTo<StringRef>());
		}
	}

	// Returns true if any options have been set
	bool hasAnyOptionsEnabled() const { return !transactionOptions.options.empty(); }

	// Prints a list of enabled options, along with their parameters (if any)
	void print() const {
		bool found = false;
		found = found || transactionOptions.print();

		if (!found)
			printf("There are no options enabled\n");
	}

	// Returns a vector of the names of all documented options
	std::vector<std::string> getValidOptions() const { return transactionOptions.getValidOptions(); }

	// Prints the help string obtained by invoking `help options'
	void printHelpString() const { transactionOptions.printHelpString(); }

private:
	// Sets a transaction option. If intrans == true, then this option is also applied to the passed in transaction.
	void setTransactionOption(Reference<ReadYourWritesTransaction> tr,
	                          FDBTransactionOptions::Option option,
	                          bool enabled,
	                          Optional<StringRef> arg,
	                          bool intrans) {
		if (enabled && arg.present() != FDBTransactionOptions::optionInfo.getMustExist(option).hasParameter) {
			fprintf(stderr, "ERROR: option %s a parameter\n", arg.present() ? "did not expect" : "expected");
			throw invalid_option_value();
		}

		if (intrans)
			tr->setOption(option, arg);

		transactionOptions.setOption(option, enabled, arg.castTo<StringRef>());
	}

	// A group of enabled options (of type T::Option) as well as a legal options map from string to T::Option
	template <class T>
	struct OptionGroup {
		std::map<typename T::Option, Optional<Standalone<StringRef>>> options;
		std::map<std::string, typename T::Option> legalOptions;

		OptionGroup<T>() {}
		OptionGroup<T>(OptionGroup<T>& base)
		  : options(base.options.begin(), base.options.end()), legalOptions(base.legalOptions) {}

		// Enable or disable an option. Returns true if option value changed
		bool setOption(typename T::Option option, bool enabled, Optional<StringRef> arg) {
			auto optionItr = options.find(option);
			if (enabled && (optionItr == options.end() ||
			                Optional<Standalone<StringRef>>(optionItr->second).castTo<StringRef>() != arg)) {
				options[option] = arg.castTo<Standalone<StringRef>>();
				return true;
			} else if (!enabled && optionItr != options.end()) {
				options.erase(optionItr);
				return true;
			}

			return false;
		}

		// Prints a list of all enabled options in this group
		bool print() const {
			bool found = false;

			for (auto itr = legalOptions.begin(); itr != legalOptions.end(); ++itr) {
				auto optionItr = options.find(itr->second);
				if (optionItr != options.end()) {
					if (optionItr->second.present())
						printf("%s: `%s'\n", itr->first.c_str(), formatStringRef(optionItr->second.get()).c_str());
					else
						printf("%s\n", itr->first.c_str());

					found = true;
				}
			}

			return found;
		}

		// Returns true if the specified option is documented
		bool isDocumented(typename T::Option option) const {
			FDBOptionInfo info = T::optionInfo.getMustExist(option);

			std::string deprecatedStr = "Deprecated";
			return !info.comment.empty() && info.comment.substr(0, deprecatedStr.size()) != deprecatedStr;
		}

		// Returns a vector of the names of all documented options
		std::vector<std::string> getValidOptions() const {
			std::vector<std::string> ret;

			for (auto itr = legalOptions.begin(); itr != legalOptions.end(); ++itr)
				if (isDocumented(itr->second))
					ret.push_back(itr->first);

			return ret;
		}

		// Prints a help string for each option in this group. Any options with no comment
		// are excluded from this help string. Lines are wrapped to 80 characters.
		void printHelpString() const {
			for (auto itr = legalOptions.begin(); itr != legalOptions.end(); ++itr) {
				if (isDocumented(itr->second)) {
					FDBOptionInfo info = T::optionInfo.getMustExist(itr->second);
					std::string helpStr = info.name + " - " + info.comment;
					if (info.hasParameter)
						helpStr += " " + info.parameterComment;
					helpStr += "\n";

					printAtCol(helpStr.c_str(), 80);
				}
			}
		}
	};

	OptionGroup<FDBTransactionOptions> transactionOptions;

public:
	FdbOptions() {
		for (auto itr = FDBTransactionOptions::optionInfo.begin(); itr != FDBTransactionOptions::optionInfo.end();
		     ++itr)
			transactionOptions.legalOptions[itr->second.name] = itr->first;
	}

	FdbOptions(FdbOptions& base) : transactionOptions(base.transactionOptions) {}
};

static std::string formatStringRef(StringRef item, bool fullEscaping = false) {
	std::string ret;

	for (int i = 0; i < item.size(); i++) {
		if (fullEscaping && item[i] == '\\')
			ret += "\\\\";
		else if (fullEscaping && item[i] == '"')
			ret += "\\\"";
		else if (fullEscaping && item[i] == ' ')
			ret += format("\\x%02x", item[i]);
		else if (item[i] >= 32 && item[i] < 127)
			ret += item[i];
		else
			ret += format("\\x%02x", item[i]);
	}

	return ret;
}

static std::vector<std::vector<StringRef>> parseLine(std::string& line, bool& err, bool& partial) {
	err = false;
	partial = false;

	bool quoted = false;
	std::vector<StringRef> buf;
	std::vector<std::vector<StringRef>> ret;

	size_t i = line.find_first_not_of(' ');
	size_t offset = i;

	bool forcetoken = false;

	while (i <= line.length()) {
		switch (line[i]) {
		case ';':
			if (!quoted) {
				if (i > offset || (forcetoken && i == offset))
					buf.push_back(StringRef((uint8_t*)(line.data() + offset), i - offset));
				ret.push_back(std::move(buf));
				offset = i = line.find_first_not_of(' ', i + 1);
				forcetoken = false;
			} else
				i++;
			break;
		case '"':
			quoted = !quoted;
			line.erase(i, 1);
			forcetoken = true;
			break;
		case ' ':
			if (!quoted) {
				if (i > offset || (forcetoken && i == offset))
					buf.push_back(StringRef((uint8_t*)(line.data() + offset), i - offset));
				offset = i = line.find_first_not_of(' ', i);
				forcetoken = false;
			} else
				i++;
			break;
		case '\\':
			if (i + 2 > line.length()) {
				err = true;
				ret.push_back(std::move(buf));
				return ret;
			}
			switch (line[i + 1]) {
				char ent, save;
			case '"':
			case '\\':
			case ' ':
			case ';':
				line.erase(i, 1);
				break;
			case 'x':
				if (i + 4 > line.length()) {
					err = true;
					ret.push_back(std::move(buf));
					return ret;
				}
				char* pEnd;
				save = line[i + 4];
				line[i + 4] = 0;
				ent = char(strtoul(line.data() + i + 2, &pEnd, 16));
				if (*pEnd) {
					err = true;
					ret.push_back(std::move(buf));
					return ret;
				}
				line[i + 4] = save;
				line.replace(i, 4, 1, ent);
				break;
			default:
				err = true;
				ret.push_back(std::move(buf));
				return ret;
			}
		default:
			i++;
		}
	}

	i -= 1;
	if (i > offset || (forcetoken && i == offset))
		buf.push_back(StringRef((uint8_t*)(line.data() + offset), i - offset));

	ret.push_back(std::move(buf));

	if (quoted)
		partial = true;

	return ret;
}

static void printProgramUsage(const char* name) {
	printf("FoundationDB CLI " FDB_VT_PACKAGE_NAME " (v" FDB_VT_VERSION ")\n"
	       "usage: %s [OPTIONS]\n"
	       "\n",
	       name);
	printf("  -C CONNFILE    The path of a file containing the connection string for the\n"
	       "                 FoundationDB cluster. The default is first the value of the\n"
	       "                 FDB_CLUSTER_FILE environment variable, then `./fdb.cluster',\n"
	       "                 then `%s'.\n",
	       platform::getDefaultClusterFilePath().c_str());
	printf("  --log          Enables trace file logging for the CLI session.\n"
	       "  --log-dir PATH Specifes the output directory for trace files. If\n"
	       "                 unspecified, defaults to the current directory. Has\n"
	       "                 no effect unless --log is specified.\n"
	       "  --trace_format FORMAT\n"
	       "                 Select the format of the log files. xml (the default) and json\n"
	       "                 are supported. Has no effect unless --log is specified.\n"
	       "  --exec CMDS    Immediately executes the semicolon separated CLI commands\n"
	       "                 and then exits.\n"
	       "  --no-status    Disables the initial status check done when starting\n"
	       "                 the CLI.\n"
#ifndef TLS_DISABLED
	       TLS_HELP
#endif
	       "  --knob_KNOBNAME KNOBVALUE\n"
	       "                 Changes a knob option. KNOBNAME should be lowercase.\n"
	       "  --debug-tls    Prints the TLS configuration and certificate chain, then exits.\n"
	       "                 Useful in reporting and diagnosing TLS issues.\n"
	       "  --build_flags  Print build information and exit.\n"
	       "  -v, --version  Print FoundationDB CLI version information and exit.\n"
	       "  -h, --help     Display this help and exit.\n");
}

#define ESCAPINGK "\n\nFor information on escaping keys, type `help escaping'."
#define ESCAPINGKV "\n\nFor information on escaping keys and values, type `help escaping'."

using namespace fdb_cli;
std::map<std::string, CommandHelp>& helpMap = CommandFactory::commands();
std::set<std::string>& hiddenCommands = CommandFactory::hiddenCommands();

void initHelp() {
	helpMap["begin"] =
	    CommandHelp("begin",
	                "begin a new transaction",
	                "By default, the fdbcli operates in autocommit mode. All operations are performed in their own "
	                "transaction, and are automatically committed for you. By explicitly beginning a transaction, "
	                "successive operations are all performed as part of a single transaction.\n\nTo commit the "
	                "transaction, use the commit command. To discard the transaction, use the reset command.");
	helpMap["commit"] = CommandHelp("commit",
	                                "commit the current transaction",
	                                "Any sets or clears executed after the start of the current transaction will be "
	                                "committed to the database. On success, the committed version number is displayed. "
	                                "If commit fails, the error is displayed and the transaction must be retried.");
	helpMap["clear"] = CommandHelp(
	    "clear <KEY>",
	    "clear a key from the database",
	    "Clear succeeds even if the specified key is not present, but may fail because of conflicts." ESCAPINGK);
	helpMap["clearrange"] = CommandHelp(
	    "clearrange <BEGINKEY> <ENDKEY>",
	    "clear a range of keys from the database",
	    "All keys between BEGINKEY (inclusive) and ENDKEY (exclusive) are cleared from the database. This command will "
	    "succeed even if the specified range is empty, but may fail because of conflicts." ESCAPINGK);
	helpMap["configure"] = CommandHelp(
	    "configure [new|tss]"
	    "<single|double|triple|three_data_hall|three_datacenter|ssd|memory|memory-radixtree-beta|proxies=<PROXIES>|"
	    "commit_proxies=<COMMIT_PROXIES>|grv_proxies=<GRV_PROXIES>|logs=<LOGS>|resolvers=<RESOLVERS>>*|"
	    "count=<TSS_COUNT>|perpetual_storage_wiggle=<WIGGLE_SPEED>",
	    "change the database configuration",
	    "The `new' option, if present, initializes a new database with the given configuration rather than changing "
	    "the configuration of an existing one. When used, both a redundancy mode and a storage engine must be "
	    "specified.\n\ntss: when enabled, configures the testing storage server for the cluster instead."
	    "When used with new to set up tss for the first time, it requires both a count and a storage engine."
	    "To disable the testing storage server, run \"configure tss count=0\"\n\n"
	    "Redundancy mode:\n  single - one copy of the data.  Not fault tolerant.\n  double - two copies "
	    "of data (survive one failure).\n  triple - three copies of data (survive two failures).\n  three_data_hall - "
	    "See the Admin Guide.\n  three_datacenter - See the Admin Guide.\n\nStorage engine:\n  ssd - B-Tree storage "
	    "engine optimized for solid state disks.\n  memory - Durable in-memory storage engine for small "
	    "datasets.\n\nproxies=<PROXIES>: Sets the desired number of proxies in the cluster. The proxy role is being "
	    "deprecated and split into GRV proxy and Commit proxy, now prefer configure 'grv_proxies' and 'commit_proxies' "
	    "separately. Generally we should follow that 'commit_proxies' is three times of 'grv_proxies' and "
	    "'grv_proxies' "
	    "should be not more than 4. If 'proxies' is specified, it will be converted to 'grv_proxies' and "
	    "'commit_proxies'. "
	    "Must be at least 2 (1 GRV proxy, 1 Commit proxy), or set to -1 which restores the number of proxies to the "
	    "default value.\n\ncommit_proxies=<COMMIT_PROXIES>: Sets the desired number of commit proxies in the cluster. "
	    "Must be at least 1, or set to -1 which restores the number of commit proxies to the default "
	    "value.\n\ngrv_proxies=<GRV_PROXIES>: Sets the desired number of GRV proxies in the cluster. Must be at least "
	    "1, or set to -1 which restores the number of GRV proxies to the default value.\n\nlogs=<LOGS>: Sets the "
	    "desired number of log servers in the cluster. Must be at least 1, or set to -1 which restores the number of "
	    "logs to the default value.\n\nresolvers=<RESOLVERS>: Sets the desired number of resolvers in the cluster. "
	    "Must be at least 1, or set to -1 which restores the number of resolvers to the default value.\n\n"
	    "perpetual_storage_wiggle=<WIGGLE_SPEED>: Set the value speed (a.k.a., the number of processes that the Data "
	    "Distributor should wiggle at a time). Currently, only 0 and 1 are supported. The value 0 means to disable the "
	    "perpetual storage wiggle.\n\n"
	    "See the FoundationDB Administration Guide for more information.");
	helpMap["fileconfigure"] = CommandHelp(
	    "fileconfigure [new] <FILENAME>",
	    "change the database configuration from a file",
	    "The `new' option, if present, initializes a new database with the given configuration rather than changing "
	    "the configuration of an existing one. Load a JSON document from the provided file, and change the database "
	    "configuration to match the contents of the JSON document. The format should be the same as the value of the "
	    "\"configuration\" entry in status JSON without \"excluded_servers\" or \"coordinators_count\".");
	helpMap["coordinators"] = CommandHelp(
	    "coordinators auto|<ADDRESS>+ [description=new_cluster_description]",
	    "change cluster coordinators or description",
	    "If 'auto' is specified, coordinator addresses will be choosen automatically to support the configured "
	    "redundancy level. (If the current set of coordinators are healthy and already support the redundancy level, "
	    "nothing will be changed.)\n\nOtherwise, sets the coordinators to the list of IP:port pairs specified by "
	    "<ADDRESS>+. An fdbserver process must be running on each of the specified addresses.\n\ne.g. coordinators "
	    "10.0.0.1:4000 10.0.0.2:4000 10.0.0.3:4000\n\nIf 'description=desc' is specified then the description field in "
	    "the cluster\nfile is changed to desc, which must match [A-Za-z0-9_]+.");
	helpMap["exclude"] = CommandHelp(
	    "exclude [FORCE] [failed] [no_wait] [<ADDRESS...>] [locality_dcid:<excludedcid>] "
	    "[locality_zoneid:<excludezoneid>] [locality_machineid:<excludemachineid>] "
	    "[locality_processid:<excludeprocessid>] or any locality data",
	    "exclude servers from the database either with IP address match or locality match",
	    "If no addresses or locaities are specified, lists the set of excluded addresses and localities."
	    "\n\nFor each IP address or IP:port pair in <ADDRESS...> or any LocalityData attributes (like dcid, zoneid, "
	    "machineid, processid), adds the address/locality to the set of excluded servers and localities then waits "
	    "until all database state has been safely moved away from the specified servers. If 'no_wait' is set, the "
	    "command returns \nimmediately without checking if the exclusions have completed successfully.\n"
	    "If 'FORCE' is set, the command does not perform safety checks before excluding.\n"
	    "If 'failed' is set, the transaction log queue is dropped pre-emptively before waiting\n"
	    "for data movement to finish and the server cannot be included again.");
	helpMap["include"] = CommandHelp(
	    "include all|[<ADDRESS...>] [locality_dcid:<excludedcid>] [locality_zoneid:<excludezoneid>] "
	    "[locality_machineid:<excludemachineid>] [locality_processid:<excludeprocessid>] or any locality data",
	    "permit previously-excluded servers and localities to rejoin the database",
	    "If `all' is specified, the excluded servers and localities list is cleared.\n\nFor each IP address or IP:port "
	    "pair in <ADDRESS...> or any LocalityData (like dcid, zoneid, machineid, processid), removes any "
	    "matching exclusions from the excluded servers and localities list. "
	    "(A specified IP will match all IP:* exclusion entries)");
	helpMap["status"] =
	    CommandHelp("status [minimal|details|json]",
	                "get the status of a FoundationDB cluster",
	                "If the cluster is down, this command will print a diagnostic which may be useful in figuring out "
	                "what is wrong. If the cluster is running, this command will print cluster "
	                "statistics.\n\nSpecifying `minimal' will provide a minimal description of the status of your "
	                "database.\n\nSpecifying `details' will provide load information for individual "
	                "workers.\n\nSpecifying `json' will provide status information in a machine readable JSON format.");
	helpMap["exit"] = CommandHelp("exit", "exit the CLI", "");
	helpMap["quit"] = CommandHelp();
	helpMap["waitconnected"] = CommandHelp();
	helpMap["waitopen"] = CommandHelp();
	helpMap["sleep"] = CommandHelp("sleep <SECONDS>", "sleep for a period of time", "");
	helpMap["get"] =
	    CommandHelp("get <KEY>",
	                "fetch the value for a given key",
	                "Displays the value of KEY in the database, or `not found' if KEY is not present." ESCAPINGK);
	helpMap["getrange"] =
	    CommandHelp("getrange <BEGINKEY> [ENDKEY] [LIMIT]",
	                "fetch key/value pairs in a range of keys",
	                "Displays up to LIMIT keys and values for keys between BEGINKEY (inclusive) and ENDKEY "
	                "(exclusive). If ENDKEY is omitted, then the range will include all keys starting with BEGINKEY. "
	                "LIMIT defaults to 25 if omitted." ESCAPINGK);
	helpMap["getrangekeys"] = CommandHelp(
	    "getrangekeys <BEGINKEY> [ENDKEY] [LIMIT]",
	    "fetch keys in a range of keys",
	    "Displays up to LIMIT keys for keys between BEGINKEY (inclusive) and ENDKEY (exclusive). If ENDKEY is omitted, "
	    "then the range will include all keys starting with BEGINKEY. LIMIT defaults to 25 if omitted." ESCAPINGK);
	helpMap["getversion"] =
	    CommandHelp("getversion",
	                "Fetch the current read version",
	                "Displays the current read version of the database or currently running transaction.");
	helpMap["reset"] =
	    CommandHelp("reset",
	                "reset the current transaction",
	                "Any sets or clears executed after the start of the active transaction will be discarded.");
	helpMap["rollback"] = CommandHelp("rollback",
	                                  "rolls back the current transaction",
	                                  "The active transaction will be discarded, including any sets or clears executed "
	                                  "since the transaction was started.");
	helpMap["set"] = CommandHelp("set <KEY> <VALUE>",
	                             "set a value for a given key",
	                             "If KEY is not already present in the database, it will be created." ESCAPINGKV);
	helpMap["option"] = CommandHelp(
	    "option <STATE> <OPTION> <ARG>",
	    "enables or disables an option",
	    "If STATE is `on', then the option OPTION will be enabled with optional parameter ARG, if required. If STATE "
	    "is `off', then OPTION will be disabled.\n\nIf there is no active transaction, then the option will be applied "
	    "to all operations as well as all subsequently created transactions (using `begin').\n\nIf there is an active "
	    "transaction (one created with `begin'), then enabled options apply only to that transaction. Options cannot "
	    "be disabled on an active transaction.\n\nCalling `option' with no parameters prints a list of all enabled "
	    "options.\n\nFor information about specific options that can be set, type `help options'.");
	helpMap["help"] = CommandHelp("help [<topic>]", "get help about a topic or command", "");
	helpMap["writemode"] = CommandHelp("writemode <on|off>",
	                                   "enables or disables sets and clears",
	                                   "Setting or clearing keys from the CLI is not recommended.");
	helpMap["kill"] = CommandHelp(
	    "kill all|list|<ADDRESS...>",
	    "attempts to kill one or more processes in the cluster",
	    "If no addresses are specified, populates the list of processes which can be killed. Processes cannot be "
	    "killed before this list has been populated.\n\nIf `all' is specified, attempts to kill all known "
	    "processes.\n\nIf `list' is specified, displays all known processes. This is only useful when the database is "
	    "unresponsive.\n\nFor each IP:port pair in <ADDRESS ...>, attempt to kill the specified process.");
	helpMap["suspend"] = CommandHelp(
	    "suspend <SECONDS> <ADDRESS...>",
	    "attempts to suspend one or more processes in the cluster",
	    "If no parameters are specified, populates the list of processes which can be suspended. Processes cannot be "
	    "suspended before this list has been populated.\n\nFor each IP:port pair in <ADDRESS...>, attempt to suspend "
	    "the processes for the specified SECONDS after which the process will die.");
	helpMap["profile"] = CommandHelp("profile <client|list|flow|heap> <action> <ARGS>",
	                                 "namespace for all the profiling-related commands.",
	                                 "Different types support different actions.  Run `profile` to get a list of "
	                                 "types, and iteratively explore the help.\n");
	helpMap["cache_range"] = CommandHelp(
	    "cache_range <set|clear> <BEGINKEY> <ENDKEY>",
	    "Mark a key range to add to or remove from storage caches.",
	    "Use the storage caches to assist in balancing hot read shards. Set the appropriate ranges when experiencing "
	    "heavy load, and clear them when they are no longer necessary.");
	helpMap["lock"] = CommandHelp(
	    "lock",
	    "lock the database with a randomly generated lockUID",
	    "Randomly generates a lockUID, prints this lockUID, and then uses the lockUID to lock the database.");
	helpMap["unlock"] =
	    CommandHelp("unlock <UID>",
	                "unlock the database with the provided lockUID",
	                "Unlocks the database with the provided lockUID. This is a potentially dangerous operation, so the "
	                "user will be asked to enter a passphrase to confirm their intent.");
	helpMap["triggerddteaminfolog"] =
	    CommandHelp("triggerddteaminfolog",
	                "trigger the data distributor teams logging",
	                "Trigger the data distributor to log detailed information about its teams.");
	helpMap["tssq"] =
	    CommandHelp("tssq start|stop <StorageUID>",
	                "start/stop tss quarantine",
	                "Toggles Quarantine mode for a Testing Storage Server. Quarantine will happen automatically if the "
	                "TSS is detected to have incorrect data, but can also be initiated manually. You can also remove a "
	                "TSS from quarantine once your investigation is finished, which will destroy the TSS process.");

	hiddenCommands.insert("expensive_data_check");
	hiddenCommands.insert("datadistribution");
}

void printVersion() {
	printf("FoundationDB CLI " FDB_VT_PACKAGE_NAME " (v" FDB_VT_VERSION ")\n");
	printf("source version %s\n", getSourceVersion());
	printf("protocol %" PRIx64 "\n", currentProtocolVersion.version());
}

void printBuildInformation() {
	printf("%s", jsonBuildInformation().c_str());
}

void printHelpOverview() {
	printf("\nList of commands:\n\n");
	for (const auto& [command, help] : helpMap) {
		if (help.short_desc.size())
			printf(" %s:\n      %s\n", command.c_str(), help.short_desc.c_str());
	}
	printf("\nFor information on a specific command, type `help <command>'.");
	printf("\nFor information on escaping keys and values, type `help escaping'.");
	printf("\nFor information on available options, type `help options'.\n\n");
}

void printHelp(StringRef command) {
	auto i = helpMap.find(command.toString());
	if (i != helpMap.end() && i->second.short_desc.size()) {
		printf("\n%s\n\n", i->second.usage.c_str());
		auto cstr = i->second.short_desc.c_str();
		printf("%c%s.\n", toupper(cstr[0]), cstr + 1);
		if (!i->second.long_desc.empty()) {
			printf("\n");
			printAtCol(i->second.long_desc.c_str(), 80);
		}
		printf("\n");
	} else
		printf("I don't know anything about `%s'\n", formatStringRef(command).c_str());
}

std::string getCoordinatorsInfoString(StatusObjectReader statusObj) {
	std::string outputString;
	try {
		StatusArray coordinatorsArr = statusObj["client.coordinators.coordinators"].get_array();
		for (StatusObjectReader coor : coordinatorsArr)
			outputString += format("\n  %s  (%s)",
			                       coor["address"].get_str().c_str(),
			                       coor["reachable"].get_bool() ? "reachable" : "unreachable");
	} catch (std::runtime_error&) {
		outputString = "\n  Unable to retrieve list of coordination servers";
	}

	return outputString;
}

std::string getDateInfoString(StatusObjectReader statusObj, std::string key) {
	time_t curTime;
	if (!statusObj.has(key)) {
		return "";
	}
	curTime = statusObj.last().get_int64();
	char buffer[128];
	struct tm* timeinfo;
	timeinfo = localtime(&curTime);
	strftime(buffer, 128, "%m/%d/%y %H:%M:%S", timeinfo);
	return std::string(buffer);
}

std::string getProcessAddressByServerID(StatusObjectReader processesMap, std::string serverID) {
	if (serverID == "")
		return "unknown";

	for (auto proc : processesMap.obj()) {
		try {
			StatusArray rolesArray = proc.second.get_obj()["roles"].get_array();
			for (StatusObjectReader role : rolesArray) {
				if (role["id"].get_str().find(serverID) == 0) {
					// If this next line throws, then we found the serverID but the role has no address, so the role is
					// skipped.
					return proc.second.get_obj()["address"].get_str();
				}
			}
		} catch (std::exception&) {
			// If an entry in the process map is badly formed then something will throw. Since we are
			// looking for a positive match, just ignore any read execeptions and move on to the next proc
		}
	}
	return "unknown";
}

std::string getWorkloadRates(StatusObjectReader statusObj,
                             bool unknown,
                             std::string first,
                             std::string second,
                             bool transactionSection = false) {
	// Re-point statusObj at either the transactions sub-doc or the operations sub-doc depending on transactionSection
	// flag
	if (transactionSection) {
		if (!statusObj.get("transactions", statusObj))
			return "unknown";
	} else {
		if (!statusObj.get("operations", statusObj))
			return "unknown";
	}

	std::string path = first + "." + second;
	double value;
	if (!unknown && statusObj.get(path, value)) {
		return format("%d Hz", (int)round(value));
	}
	return "unknown";
}

void getBackupDRTags(StatusObjectReader& statusObjCluster,
                     const char* context,
                     std::map<std::string, std::string>& tagMap) {
	std::string path = format("layers.%s.tags", context);
	StatusObjectReader tags;
	if (statusObjCluster.tryGet(path, tags)) {
		for (auto itr : tags.obj()) {
			JSONDoc tag(itr.second);
			bool running = false;
			tag.tryGet("running_backup", running);
			if (running) {
				std::string uid;
				if (tag.tryGet("mutation_stream_id", uid)) {
					tagMap[itr.first] = uid;
				} else {
					tagMap[itr.first] = "";
				}
			}
		}
	}
}

std::string logBackupDR(const char* context, std::map<std::string, std::string> const& tagMap) {
	std::string outputString = "";
	if (tagMap.size() > 0) {
		outputString += format("\n\n%s:", context);
		for (auto itr : tagMap) {
			outputString += format("\n  %-22s", itr.first.c_str());
			if (itr.second.size() > 0) {
				outputString += format(" - %s", itr.second.c_str());
			}
		}
	}

	return outputString;
}

int getNumofNonExcludedMachines(StatusObjectReader statusObjCluster) {
	StatusObjectReader machineMap;
	int numOfNonExcludedMachines = 0;
	if (statusObjCluster.get("machines", machineMap)) {
		for (auto mach : machineMap.obj()) {
			StatusObjectReader machine(mach.second);
			if (machine.has("excluded") && !machine.last().get_bool())
				numOfNonExcludedMachines++;
		}
	}
	return numOfNonExcludedMachines;
}

std::pair<int, int> getNumOfNonExcludedProcessAndZones(StatusObjectReader statusObjCluster) {
	StatusObjectReader processesMap;
	std::set<std::string> zones;
	int numOfNonExcludedProcesses = 0;
	if (statusObjCluster.get("processes", processesMap)) {
		for (auto proc : processesMap.obj()) {
			StatusObjectReader process(proc.second);
			if (process.has("excluded") && process.last().get_bool())
				continue;
			numOfNonExcludedProcesses++;
			std::string zoneId;
			if (process.get("locality.zoneid", zoneId)) {
				zones.insert(zoneId);
			}
		}
	}
	return { numOfNonExcludedProcesses, zones.size() };
}

void printStatus(StatusObjectReader statusObj,
                 StatusClient::StatusLevel level,
                 bool displayDatabaseAvailable = true,
                 bool hideErrorMessages = false) {
	if (FlowTransport::transport().incompatibleOutgoingConnectionsPresent()) {
		fprintf(
		    stderr,
		    "WARNING: One or more of the processes in the cluster is incompatible with this version of fdbcli.\n\n");
	}

	try {
		bool printedCoordinators = false;

		// status or status details
		if (level == StatusClient::NORMAL || level == StatusClient::DETAILED) {

			StatusObjectReader statusObjClient;
			statusObj.get("client", statusObjClient);

			// The way the output string is assembled is to add new line character before addition to the string rather
			// than after
			std::string outputString = "";
			std::string clusterFilePath;
			if (statusObjClient.get("cluster_file.path", clusterFilePath))
				outputString = format("Using cluster file `%s'.\n", clusterFilePath.c_str());
			else
				outputString = "Using unknown cluster file.\n";

			StatusObjectReader statusObjCoordinators;
			StatusArray coordinatorsArr;

			if (statusObjClient.get("coordinators", statusObjCoordinators)) {
				// Look for a second "coordinators", under the first one.
				if (statusObjCoordinators.has("coordinators"))
					coordinatorsArr = statusObjCoordinators.last().get_array();
			}

			// Check if any coordination servers are unreachable
			bool quorum_reachable;
			if (statusObjCoordinators.get("quorum_reachable", quorum_reachable) && !quorum_reachable) {
				outputString += "\nCould not communicate with a quorum of coordination servers:";
				outputString += getCoordinatorsInfoString(statusObj);

				printf("%s\n", outputString.c_str());
				return;
			} else {
				for (StatusObjectReader coor : coordinatorsArr) {
					bool reachable;
					if (coor.get("reachable", reachable) && !reachable) {
						outputString += "\nCould not communicate with all of the coordination servers."
						                "\n  The database will remain operational as long as we"
						                "\n  can connect to a quorum of servers, however the fault"
						                "\n  tolerance of the system is reduced as long as the"
						                "\n  servers remain disconnected.\n";
						outputString += getCoordinatorsInfoString(statusObj);
						outputString += "\n";
						printedCoordinators = true;
						break;
					}
				}
			}

			// print any client messages
			if (statusObjClient.has("messages")) {
				for (StatusObjectReader message : statusObjClient.last().get_array()) {
					std::string desc;
					if (message.get("description", desc))
						outputString += "\n" + lineWrap(desc.c_str(), 80);
				}
			}

			bool fatalRecoveryState = false;
			StatusObjectReader statusObjCluster;
			try {
				if (statusObj.get("cluster", statusObjCluster)) {

					StatusObjectReader recoveryState;
					if (statusObjCluster.get("recovery_state", recoveryState)) {
						std::string name;
						std::string description;
						if (recoveryState.get("name", name) && recoveryState.get("description", description) &&
						    name != "accepting_commits" && name != "all_logs_recruited" &&
						    name != "storage_recovered" && name != "fully_recovered") {
							fatalRecoveryState = true;

							if (name == "recruiting_transaction_servers") {
								description +=
								    format("\nNeed at least %d log servers across unique zones, %d commit proxies, "
								           "%d GRV proxies and %d resolvers.",
								           recoveryState["required_logs"].get_int(),
								           recoveryState["required_commit_proxies"].get_int(),
								           recoveryState["required_grv_proxies"].get_int(),
								           recoveryState["required_resolvers"].get_int());
								if (statusObjCluster.has("machines") && statusObjCluster.has("processes")) {
									auto numOfNonExcludedProcessesAndZones =
									    getNumOfNonExcludedProcessAndZones(statusObjCluster);
									description +=
									    format("\nHave %d non-excluded processes on %d machines across %d zones.",
									           numOfNonExcludedProcessesAndZones.first,
									           getNumofNonExcludedMachines(statusObjCluster),
									           numOfNonExcludedProcessesAndZones.second);
								}
							} else if (name == "locking_old_transaction_servers" &&
							           recoveryState["missing_logs"].get_str().size()) {
								description += format("\nNeed one or more of the following log servers: %s",
								                      recoveryState["missing_logs"].get_str().c_str());
							}
							description = lineWrap(description.c_str(), 80);
							if (!printedCoordinators &&
							    (name == "reading_coordinated_state" || name == "locking_coordinated_state" ||
							     name == "configuration_never_created" || name == "writing_coordinated_state")) {
								description += getCoordinatorsInfoString(statusObj);
								description += "\n";
								printedCoordinators = true;
							}

							outputString += "\n" + description;
						}
					}
				}
			} catch (std::runtime_error&) {
			}

			// Check if cluster controllable is reachable
			try {
				// print any cluster messages
				if (statusObjCluster.has("messages") && statusObjCluster.last().get_array().size()) {

					// any messages we don't want to display
					std::set<std::string> skipMsgs = { "unreachable_process", "" };
					if (fatalRecoveryState) {
						skipMsgs.insert("status_incomplete");
						skipMsgs.insert("unreadable_configuration");
						skipMsgs.insert("immediate_priority_transaction_start_probe_timeout");
						skipMsgs.insert("batch_priority_transaction_start_probe_timeout");
						skipMsgs.insert("transaction_start_probe_timeout");
						skipMsgs.insert("read_probe_timeout");
						skipMsgs.insert("commit_probe_timeout");
					}

					for (StatusObjectReader msgObj : statusObjCluster.last().get_array()) {
						std::string messageName;
						if (!msgObj.get("name", messageName)) {
							continue;
						}
						if (skipMsgs.count(messageName)) {
							continue;
						} else if (messageName == "client_issues") {
							if (msgObj.has("issues")) {
								for (StatusObjectReader issue : msgObj["issues"].get_array()) {
									std::string issueName;
									if (!issue.get("name", issueName)) {
										continue;
									}

									std::string description;
									if (!issue.get("description", description)) {
										description = issueName;
									}

									std::string countStr;
									StatusArray addresses;
									if (!issue.has("addresses")) {
										countStr = "Some client(s)";
									} else {
										addresses = issue["addresses"].get_array();
										countStr = format("%d client(s)", addresses.size());
									}
									outputString +=
									    format("\n%s reported: %s\n", countStr.c_str(), description.c_str());

									if (level == StatusClient::StatusLevel::DETAILED) {
										for (int i = 0; i < addresses.size() && i < 4; ++i) {
											outputString += format("  %s\n", addresses[i].get_str().c_str());
										}
										if (addresses.size() > 4) {
											outputString += "  ...\n";
										}
									}
								}
							}
						} else {
							if (msgObj.has("description"))
								outputString += "\n" + lineWrap(msgObj.last().get_str().c_str(), 80);
						}
					}
				}
			} catch (std::runtime_error&) {
			}

			if (fatalRecoveryState) {
				printf("%s", outputString.c_str());
				return;
			}

			StatusObjectReader statusObjConfig;
			StatusArray excludedServersArr;
			Optional<std::string> activePrimaryDC;

			if (statusObjCluster.has("active_primary_dc")) {
				activePrimaryDC = statusObjCluster["active_primary_dc"].get_str();
			}
			if (statusObjCluster.get("configuration", statusObjConfig)) {
				if (statusObjConfig.has("excluded_servers"))
					excludedServersArr = statusObjConfig.last().get_array();
			}

			// If there is a configuration message then there is no configuration information to display
			outputString += "\nConfiguration:";
			std::string outputStringCache = outputString;
			bool isOldMemory = false;
			try {
				// Configuration section
				// FIXME: Should we suppress this if there are cluster messages implying that the database has no
				// configuration?

				outputString += "\n  Redundancy mode        - ";
				std::string strVal;

				if (statusObjConfig.get("redundancy_mode", strVal)) {
					outputString += strVal;
				} else
					outputString += "unknown";

				outputString += "\n  Storage engine         - ";
				if (statusObjConfig.get("storage_engine", strVal)) {
					if (strVal == "memory-1") {
						isOldMemory = true;
					}
					outputString += strVal;
				} else
					outputString += "unknown";

				int intVal;
				outputString += "\n  Coordinators           - ";
				if (statusObjConfig.get("coordinators_count", intVal)) {
					outputString += std::to_string(intVal);
				} else
					outputString += "unknown";

				if (excludedServersArr.size()) {
					outputString += format("\n  Exclusions             - %d (type `exclude' for details)",
					                       excludedServersArr.size());
				}

				if (statusObjConfig.get("commit_proxies", intVal))
					outputString += format("\n  Desired Commit Proxies - %d", intVal);

				if (statusObjConfig.get("grv_proxies", intVal))
					outputString += format("\n  Desired GRV Proxies    - %d", intVal);

				if (statusObjConfig.get("resolvers", intVal))
					outputString += format("\n  Desired Resolvers      - %d", intVal);

				if (statusObjConfig.get("logs", intVal))
					outputString += format("\n  Desired Logs           - %d", intVal);

				if (statusObjConfig.get("remote_logs", intVal))
					outputString += format("\n  Desired Remote Logs    - %d", intVal);

				if (statusObjConfig.get("log_routers", intVal))
					outputString += format("\n  Desired Log Routers    - %d", intVal);

				if (statusObjConfig.get("tss_count", intVal) && intVal > 0) {
					int activeTss = 0;
					if (statusObjCluster.has("active_tss_count")) {
						statusObjCluster.get("active_tss_count", activeTss);
					}
					outputString += format("\n  TSS                    - %d/%d", activeTss, intVal);

					if (statusObjConfig.get("tss_storage_engine", strVal))
						outputString += format("\n  TSS Storage Engine     - %s", strVal.c_str());
				}

				outputString += "\n  Usable Regions         - ";
				if (statusObjConfig.get("usable_regions", intVal)) {
					outputString += std::to_string(intVal);
				} else {
					outputString += "unknown";
				}

				StatusArray regions;
				if (statusObjConfig.has("regions")) {
					outputString += "\n  Regions: ";
					regions = statusObjConfig["regions"].get_array();
					for (StatusObjectReader region : regions) {
						bool isPrimary = false;
						std::vector<std::string> regionSatelliteDCs;
						std::string regionDC;
						for (StatusObjectReader dc : region["datacenters"].get_array()) {
							if (!dc.has("satellite")) {
								regionDC = dc["id"].get_str();
								if (activePrimaryDC.present() && dc["id"].get_str() == activePrimaryDC.get()) {
									isPrimary = true;
								}
							} else if (dc["satellite"].get_int() == 1) {
								regionSatelliteDCs.push_back(dc["id"].get_str());
							}
						}
						if (activePrimaryDC.present()) {
							if (isPrimary) {
								outputString += "\n    Primary -";
							} else {
								outputString += "\n    Remote -";
							}
						} else {
							outputString += "\n    Region -";
						}
						outputString += format("\n        Datacenter                    - %s", regionDC.c_str());
						if (regionSatelliteDCs.size() > 0) {
							outputString += "\n        Satellite datacenters         - ";
							for (int i = 0; i < regionSatelliteDCs.size(); i++) {
								if (i != regionSatelliteDCs.size() - 1) {
									outputString += format("%s, ", regionSatelliteDCs[i].c_str());
								} else {
									outputString += format("%s", regionSatelliteDCs[i].c_str());
								}
							}
						}
						isPrimary = false;
						if (region.get("satellite_redundancy_mode", strVal)) {
							outputString += format("\n        Satellite Redundancy Mode     - %s", strVal.c_str());
						}
						if (region.get("satellite_anti_quorum", intVal)) {
							outputString += format("\n        Satellite Anti Quorum         - %d", intVal);
						}
						if (region.get("satellite_logs", intVal)) {
							outputString += format("\n        Satellite Logs                - %d", intVal);
						}
						if (region.get("satellite_log_policy", strVal)) {
							outputString += format("\n        Satellite Log Policy          - %s", strVal.c_str());
						}
						if (region.get("satellite_log_replicas", intVal)) {
							outputString += format("\n        Satellite Log Replicas        - %d", intVal);
						}
						if (region.get("satellite_usable_dcs", intVal)) {
							outputString += format("\n        Satellite Usable DCs          - %d", intVal);
						}
					}
				}
			} catch (std::runtime_error&) {
				outputString = outputStringCache;
				outputString += "\n  Unable to retrieve configuration status";
			}

			// Cluster section
			outputString += "\n\nCluster:";
			StatusObjectReader processesMap;
			StatusObjectReader machinesMap;

			outputStringCache = outputString;

			bool machinesAreZones = true;
			std::map<std::string, int> zones;
			try {
				outputString += "\n  FoundationDB processes - ";
				if (statusObjCluster.get("processes", processesMap)) {

					outputString += format("%d", processesMap.obj().size());

					int errors = 0;
					int processExclusions = 0;
					for (auto p : processesMap.obj()) {
						StatusObjectReader process(p.second);
						bool excluded = process.has("excluded") && process.last().get_bool();
						if (excluded) {
							processExclusions++;
						}
						if (process.has("messages") && process.last().get_array().size()) {
							errors++;
						}

						std::string zoneId;
						if (process.get("locality.zoneid", zoneId)) {
							std::string machineId;
							if (!process.get("locality.machineid", machineId) || machineId != zoneId) {
								machinesAreZones = false;
							}
							int& nonExcluded = zones[zoneId];
							if (!excluded) {
								nonExcluded = 1;
							}
						}
					}

					if (errors > 0 || processExclusions) {
						outputString += format(" (less %d excluded; %d with errors)", processExclusions, errors);
					}

				} else
					outputString += "unknown";

				if (zones.size() > 0) {
					outputString += format("\n  Zones                  - %d", zones.size());
					int zoneExclusions = 0;
					for (auto itr : zones) {
						if (itr.second == 0) {
							++zoneExclusions;
						}
					}
					if (zoneExclusions > 0) {
						outputString += format(" (less %d excluded)", zoneExclusions);
					}
				} else {
					outputString += "\n  Zones                  - unknown";
				}

				outputString += "\n  Machines               - ";
				if (statusObjCluster.get("machines", machinesMap)) {
					outputString += format("%d", machinesMap.obj().size());

					int machineExclusions = 0;
					for (auto mach : machinesMap.obj()) {
						StatusObjectReader machine(mach.second);
						if (machine.has("excluded") && machine.last().get_bool())
							machineExclusions++;
					}

					if (machineExclusions) {
						outputString += format(" (less %d excluded)", machineExclusions);
					}

					int64_t minMemoryAvailable = std::numeric_limits<int64_t>::max();
					for (auto proc : processesMap.obj()) {
						StatusObjectReader process(proc.second);
						int64_t availBytes;
						if (process.get("memory.available_bytes", availBytes)) {
							minMemoryAvailable = std::min(minMemoryAvailable, availBytes);
						}
					}

					if (minMemoryAvailable < std::numeric_limits<int64_t>::max()) {
						double worstServerGb = minMemoryAvailable / (1024.0 * 1024 * 1024);
						outputString += "\n  Memory availability    - ";
						outputString += format("%.1f GB per process on machine with least available", worstServerGb);
						outputString += minMemoryAvailable < 4294967296
						                    ? "\n                           >>>>> (WARNING: 4.0 GB recommended) <<<<<"
						                    : "";
					}

					double retransCount = 0;
					for (auto mach : machinesMap.obj()) {
						StatusObjectReader machine(mach.second);
						double hz;
						if (machine.get("network.tcp_segments_retransmitted.hz", hz))
							retransCount += hz;
					}

					if (retransCount > 0) {
						outputString += format("\n  Retransmissions rate   - %d Hz", (int)round(retransCount));
					}
				} else
					outputString += "\n  Machines               - unknown";

				StatusObjectReader faultTolerance;
				if (statusObjCluster.get("fault_tolerance", faultTolerance)) {
					int availLoss, dataLoss;

					if (faultTolerance.get("max_zone_failures_without_losing_availability", availLoss) &&
					    faultTolerance.get("max_zone_failures_without_losing_data", dataLoss)) {

						outputString += "\n  Fault Tolerance        - ";

						int minLoss = std::min(availLoss, dataLoss);
						const char* faultDomain = machinesAreZones ? "machine" : "zone";
						outputString += format("%d %ss", minLoss, faultDomain);

						if (dataLoss > availLoss) {
							outputString += format(" (%d without data loss)", dataLoss);
						}

						if (dataLoss == -1) {
							ASSERT_WE_THINK(availLoss == -1);
							outputString += format(
							    "\n\n  Warning: the database may have data loss and availability loss. Please restart "
							    "following tlog interfaces, otherwise storage servers may never be able to catch "
							    "up.\n");
							StatusObjectReader logs;
							if (statusObjCluster.has("logs")) {
								for (StatusObjectReader logEpoch : statusObjCluster.last().get_array()) {
									bool possiblyLosingData;
									if (logEpoch.get("possibly_losing_data", possiblyLosingData) &&
									    !possiblyLosingData) {
										continue;
									}
									// Current epoch doesn't have an end version.
									int64_t epoch, beginVersion, endVersion = invalidVersion;
									bool current;
									logEpoch.get("epoch", epoch);
									logEpoch.get("begin_version", beginVersion);
									logEpoch.get("end_version", endVersion);
									logEpoch.get("current", current);
									std::string missing_log_interfaces;
									if (logEpoch.has("log_interfaces")) {
										for (StatusObjectReader logInterface : logEpoch.last().get_array()) {
											bool healthy;
											std::string address, id;
											if (logInterface.get("healthy", healthy) && !healthy) {
												logInterface.get("id", id);
												logInterface.get("address", address);
												missing_log_interfaces += format("%s,%s ", id.c_str(), address.c_str());
											}
										}
									}
									outputString += format(
									    "  %s log epoch: %ld begin: %ld end: %s, missing "
									    "log interfaces(id,address): %s\n",
									    current ? "Current" : "Old",
									    epoch,
									    beginVersion,
									    endVersion == invalidVersion ? "(unknown)" : format("%ld", endVersion).c_str(),
									    missing_log_interfaces.c_str());
								}
							}
						}
					}
				}

				std::string serverTime = getDateInfoString(statusObjCluster, "cluster_controller_timestamp");
				if (serverTime != "") {
					outputString += "\n  Server time            - " + serverTime;
				}
			} catch (std::runtime_error&) {
				outputString = outputStringCache;
				outputString += "\n  Unable to retrieve cluster status";
			}

			StatusObjectReader statusObjData;
			statusObjCluster.get("data", statusObjData);

			// Data section
			outputString += "\n\nData:";
			outputStringCache = outputString;
			try {
				outputString += "\n  Replication health     - ";

				StatusObjectReader statusObjDataState;
				statusObjData.get("state", statusObjDataState);

				std::string dataState;
				statusObjDataState.get("name", dataState);

				std::string description = "";
				statusObjDataState.get("description", description);

				bool healthy;
				if (statusObjDataState.get("healthy", healthy) && healthy) {
					outputString += "Healthy" + (description != "" ? " (" + description + ")" : "");
				} else if (dataState == "missing_data") {
					outputString += "UNHEALTHY" + (description != "" ? ": " + description : "");
				} else if (dataState == "healing") {
					outputString += "HEALING" + (description != "" ? ": " + description : "");
				} else if (description != "") {
					outputString += description;
				} else {
					outputString += "unknown";
				}

				if (statusObjData.has("moving_data")) {
					StatusObjectReader movingData = statusObjData.last();
					double dataInQueue, dataInFlight;
					if (movingData.get("in_queue_bytes", dataInQueue) &&
					    movingData.get("in_flight_bytes", dataInFlight))
						outputString += format("\n  Moving data            - %.3f GB",
						                       ((double)dataInQueue + (double)dataInFlight) / 1e9);
				} else if (dataState == "initializing") {
					outputString += "\n  Moving data            - unknown (initializing)";
				} else {
					outputString += "\n  Moving data            - unknown";
				}

				outputString += "\n  Sum of key-value sizes - ";

				if (statusObjData.has("total_kv_size_bytes")) {
					double totalDBBytes = statusObjData.last().get_int64();

					if (totalDBBytes >= 1e12)
						outputString += format("%.3f TB", (totalDBBytes / 1e12));

					else if (totalDBBytes >= 1e9)
						outputString += format("%.3f GB", (totalDBBytes / 1e9));

					else
						// no decimal points for MB
						outputString += format("%d MB", (int)round(totalDBBytes / 1e6));
				} else {
					outputString += "unknown";
				}

				outputString += "\n  Disk space used        - ";

				if (statusObjData.has("total_disk_used_bytes")) {
					double totalDiskUsed = statusObjData.last().get_int64();

					if (totalDiskUsed >= 1e12)
						outputString += format("%.3f TB", (totalDiskUsed / 1e12));

					else if (totalDiskUsed >= 1e9)
						outputString += format("%.3f GB", (totalDiskUsed / 1e9));

					else
						// no decimal points for MB
						outputString += format("%d MB", (int)round(totalDiskUsed / 1e6));
				} else
					outputString += "unknown";

			} catch (std::runtime_error&) {
				outputString = outputStringCache;
				outputString += "\n  Unable to retrieve data status";
			}

			// Operating space section
			outputString += "\n\nOperating space:";
			std::string operatingSpaceString = "";
			try {
				int64_t val;
				if (statusObjData.get("least_operating_space_bytes_storage_server", val))
					operatingSpaceString += format("\n  Storage server         - %.1f GB free on most full server",
					                               std::max(val / 1e9, 0.0));

				if (statusObjData.get("least_operating_space_bytes_log_server", val))
					operatingSpaceString += format("\n  Log server             - %.1f GB free on most full server",
					                               std::max(val / 1e9, 0.0));

			} catch (std::runtime_error&) {
				operatingSpaceString = "";
			}

			if (operatingSpaceString.empty()) {
				operatingSpaceString += "\n  Unable to retrieve operating space status";
			}
			outputString += operatingSpaceString;

			// Workload section
			outputString += "\n\nWorkload:";
			outputStringCache = outputString;
			bool foundLogAndStorage = false;
			try {
				// Determine which rates are unknown
				StatusObjectReader statusObjWorkload;
				statusObjCluster.get("workload", statusObjWorkload);

				std::string performanceLimited = "";
				bool unknownMCT = false;
				bool unknownRP = false;

				// Print performance limit details if known.
				try {
					StatusObjectReader limit = statusObjCluster["qos.performance_limited_by"];
					std::string name = limit["name"].get_str();
					if (name != "workload") {
						std::string desc = limit["description"].get_str();
						std::string serverID;
						limit.get("reason_server_id", serverID);
						std::string procAddr = getProcessAddressByServerID(processesMap, serverID);
						performanceLimited = format("\n  Performance limited by %s: %s",
						                            (procAddr == "unknown")
						                                ? ("server" + (serverID == "" ? "" : (" " + serverID))).c_str()
						                                : "process",
						                            desc.c_str());
						if (procAddr != "unknown")
							performanceLimited += format("\n  Most limiting process: %s", procAddr.c_str());
					}
				} catch (std::exception&) {
					// If anything here throws (such as for an incompatible type) ignore it.
				}

				// display the known rates
				outputString += "\n  Read rate              - ";
				outputString += getWorkloadRates(statusObjWorkload, unknownRP, "reads", "hz");

				outputString += "\n  Write rate             - ";
				outputString += getWorkloadRates(statusObjWorkload, unknownMCT, "writes", "hz");

				outputString += "\n  Transactions started   - ";
				outputString += getWorkloadRates(statusObjWorkload, unknownMCT, "started", "hz", true);

				outputString += "\n  Transactions committed - ";
				outputString += getWorkloadRates(statusObjWorkload, unknownMCT, "committed", "hz", true);

				outputString += "\n  Conflict rate          - ";
				outputString += getWorkloadRates(statusObjWorkload, unknownMCT, "conflicted", "hz", true);

				outputString += unknownRP ? "" : performanceLimited;

				// display any process messages
				// FIXME:  Above comment is not what this code block does, it actually just looks for a specific message
				// in the process map, *by description*, and adds process addresses that have it to a vector.  Either
				// change the comment or the code.
				std::vector<std::string> messagesAddrs;
				for (auto proc : processesMap.obj()) {
					StatusObjectReader process(proc.second);
					if (process.has("roles")) {
						StatusArray rolesArray = proc.second.get_obj()["roles"].get_array();
						bool storageRole = false;
						bool logRole = false;
						for (StatusObjectReader role : rolesArray) {
							if (role["role"].get_str() == "storage") {
								storageRole = true;
							} else if (role["role"].get_str() == "log") {
								logRole = true;
							}
						}
						if (storageRole && logRole) {
							foundLogAndStorage = true;
						}
					}
					if (process.has("messages")) {
						StatusArray processMessagesArr = process.last().get_array();
						if (processMessagesArr.size()) {
							for (StatusObjectReader msg : processMessagesArr) {
								std::string desc;
								std::string addr;
								if (msg.get("description", desc) && desc == "Unable to update cluster file." &&
								    process.get("address", addr)) {
									messagesAddrs.push_back(addr);
								}
							}
						}
					}
				}
				if (messagesAddrs.size()) {
					outputString += format("\n\n%d FoundationDB processes reported unable to update cluster file:",
					                       messagesAddrs.size());
					for (auto msg : messagesAddrs) {
						outputString += "\n  " + msg;
					}
				}
			} catch (std::runtime_error&) {
				outputString = outputStringCache;
				outputString += "\n  Unable to retrieve workload status";
			}

			// Backup and DR section
			outputString += "\n\nBackup and DR:";

			std::map<std::string, std::string> backupTags;
			getBackupDRTags(statusObjCluster, "backup", backupTags);

			std::map<std::string, std::string> drPrimaryTags;
			getBackupDRTags(statusObjCluster, "dr_backup", drPrimaryTags);

			std::map<std::string, std::string> drSecondaryTags;
			getBackupDRTags(statusObjCluster, "dr_backup_dest", drSecondaryTags);

			outputString += format("\n  Running backups        - %d", backupTags.size());
			outputString += format("\n  Running DRs            - ");

			if (drPrimaryTags.size() == 0 && drSecondaryTags.size() == 0) {
				outputString += format("%d", 0);
			} else {
				if (drPrimaryTags.size() > 0) {
					outputString += format("%d as primary", drPrimaryTags.size());
					if (drSecondaryTags.size() > 0) {
						outputString += ", ";
					}
				}
				if (drSecondaryTags.size() > 0) {
					outputString += format("%d as secondary", drSecondaryTags.size());
				}
			}

			// status details
			if (level == StatusClient::DETAILED) {
				outputString += logBackupDR("Running backup tags", backupTags);
				outputString += logBackupDR("Running DR tags (as primary)", drPrimaryTags);
				outputString += logBackupDR("Running DR tags (as secondary)", drSecondaryTags);

				outputString += "\n\nProcess performance details:";
				outputStringCache = outputString;
				try {
					// constructs process performance details output
					std::map<NetworkAddress, std::string> workerDetails;
					for (auto proc : processesMap.obj()) {
						StatusObjectReader procObj(proc.second);
						std::string address;
						procObj.get("address", address);

						std::string line;

						NetworkAddress parsedAddress;
						try {
							parsedAddress = NetworkAddress::parse(address);
						} catch (Error&) {
							// Groups all invalid IP address/port pair in the end of this detail group.
							line = format("  %-22s (invalid IP address or port)", address.c_str());
							IPAddress::IPAddressStore maxIp;
							for (int i = 0; i < maxIp.size(); ++i) {
								maxIp[i] = std::numeric_limits<std::remove_reference<decltype(maxIp[0])>::type>::max();
							}
							std::string& lastline =
							    workerDetails[NetworkAddress(IPAddress(maxIp), std::numeric_limits<uint16_t>::max())];
							if (!lastline.empty())
								lastline.append("\n");
							lastline += line;
							continue;
						}

						try {
							double tx = -1, rx = -1, mCPUUtil = -1;
							int64_t processTotalSize;

							// Get the machine for this process
							// StatusObjectReader mach = machinesMap[procObj["machine_id"].get_str()];
							StatusObjectReader mach;
							if (machinesMap.get(procObj["machine_id"].get_str(), mach, false)) {
								StatusObjectReader machCPU;
								if (mach.get("cpu", machCPU)) {

									machCPU.get("logical_core_utilization", mCPUUtil);

									StatusObjectReader network;
									if (mach.get("network", network)) {
										network.get("megabits_sent.hz", tx);
										network.get("megabits_received.hz", rx);
									}
								}
							}

							procObj.get("memory.used_bytes", processTotalSize);

							StatusObjectReader procCPUObj;
							procObj.get("cpu", procCPUObj);

							line = format("  %-22s (", address.c_str());

							double usageCores;
							if (procCPUObj.get("usage_cores", usageCores))
								line += format("%3.0f%% cpu;", usageCores * 100);

							line += mCPUUtil != -1 ? format("%3.0f%% machine;", mCPUUtil * 100) : "";
							line += std::min(tx, rx) != -1 ? format("%6.3f Gbps;", std::max(tx, rx) / 1000.0) : "";

							double diskBusy;
							if (procObj.get("disk.busy", diskBusy))
								line += format("%3.0f%% disk IO;", 100.0 * diskBusy);

							line += processTotalSize != -1
							            ? format("%4.1f GB", processTotalSize / (1024.0 * 1024 * 1024))
							            : "";

							double availableBytes;
							if (procObj.get("memory.available_bytes", availableBytes))
								line += format(" / %3.1f GB RAM  )", availableBytes / (1024.0 * 1024 * 1024));
							else
								line += "  )";

							if (procObj.has("messages")) {
								for (StatusObjectReader message : procObj.last().get_array()) {
									std::string desc;
									if (message.get("description", desc)) {
										if (message.has("type")) {
											line += "\n    Last logged error: " + desc;
										} else {
											line += "\n    " + desc;
										}
									}
								}
							}

							workerDetails[parsedAddress] = line;
						}

						catch (std::runtime_error&) {
							std::string noMetrics = format("  %-22s (no metrics available)", address.c_str());
							workerDetails[parsedAddress] = noMetrics;
						}
					}
					for (auto w : workerDetails)
						outputString += "\n" + format("%s", w.second.c_str());
				} catch (std::runtime_error&) {
					outputString = outputStringCache;
					outputString += "\n  Unable to retrieve process performance details";
				}

				if (!printedCoordinators) {
					printedCoordinators = true;
					outputString += "\n\nCoordination servers:";
					outputString += getCoordinatorsInfoString(statusObj);
				}
			}

			// client time
			std::string clientTime = getDateInfoString(statusObjClient, "timestamp");
			if (clientTime != "") {
				outputString += "\n\nClient time: " + clientTime;
			}

			if (processesMap.obj().size() > 1 && isOldMemory) {
				outputString += "\n\nWARNING: type `configure memory' to switch to a safer method of persisting data "
				                "on the transaction logs.";
			}
			if (processesMap.obj().size() > 9 && foundLogAndStorage) {
				outputString +=
				    "\n\nWARNING: A single process is both a transaction log and a storage server.\n  For best "
				    "performance use dedicated disks for the transaction logs by setting process classes.";
			}

			if (statusObjCluster.has("data_distribution_disabled")) {
				outputString += "\n\nWARNING: Data distribution is off.";
			} else {
				if (statusObjCluster.has("data_distribution_disabled_for_ss_failures")) {
					outputString += "\n\nWARNING: Data distribution is currently turned on but disabled for all "
					                "storage server failures.";
				}
				if (statusObjCluster.has("data_distribution_disabled_for_rebalance")) {
					outputString += "\n\nWARNING: Data distribution is currently turned on but shard size balancing is "
					                "currently disabled.";
				}
			}

			printf("%s\n", outputString.c_str());
		}

		// status minimal
		else if (level == StatusClient::MINIMAL) {
			// Checking for field exsistence is not necessary here because if a field is missing there is no additional
			// information that we would be able to display if we continued execution. Instead, any missing fields will
			// throw and the catch will display the proper message.
			try {
				// If any of these throw, can't get status because the result makes no sense.
				StatusObjectReader statusObjClient = statusObj["client"].get_obj();
				StatusObjectReader statusObjClientDatabaseStatus = statusObjClient["database_status"].get_obj();

				bool available = statusObjClientDatabaseStatus["available"].get_bool();

				// Database unavailable
				if (!available) {
					printf("%s", "The database is unavailable; type `status' for more information.\n");
				} else {
					try {
						bool healthy = statusObjClientDatabaseStatus["healthy"].get_bool();

						// Database available without issues
						if (healthy) {
							if (displayDatabaseAvailable) {
								printf("The database is available.\n");
							}
						} else { // Database running but with issues
							printf("The database is available, but has issues (type 'status' for more information).\n");
						}
					} catch (std::runtime_error&) {
						printf("The database is available, but has issues (type 'status' for more information).\n");
					}
				}

				bool upToDate;
				if (!statusObjClient.get("cluster_file.up_to_date", upToDate) || !upToDate) {
					fprintf(stderr,
					        "WARNING: The cluster file is not up to date. Type 'status' for more information.\n");
				}
			} catch (std::runtime_error&) {
				printf("Unable to determine database state, type 'status' for more information.\n");
			}

		}

		// status JSON
		else if (level == StatusClient::JSON) {
			printf("%s\n",
			       json_spirit::write_string(json_spirit::mValue(statusObj.obj()),
			                                 json_spirit::Output_options::pretty_print)
			           .c_str());
		}
	} catch (Error&) {
		if (hideErrorMessages)
			return;
		if (level == StatusClient::MINIMAL) {
			printf("Unable to determine database state, type 'status' for more information.\n");
		} else if (level == StatusClient::JSON) {
			printf("Could not retrieve status json.\n\n");
		} else {
			printf("Could not retrieve status, type 'status json' for more information.\n");
		}
	}
	return;
}

int printStatusFromJSON(std::string const& jsonFileName) {
	try {
		json_spirit::mValue value;
		json_spirit::read_string(readFileBytes(jsonFileName, 10000000), value);

		printStatus(value.get_obj(), StatusClient::DETAILED, false, true);

		return 0;
	} catch (std::exception& e) {
		printf("Exception printing status: %s\n", e.what());
		return 1;
	} catch (Error& e) {
		printf("Error printing status: %d %s\n", e.code(), e.what());
		return 2;
	} catch (...) {
		printf("Unknown exception printing status.\n");
		return 3;
	}
}

ACTOR Future<Void> triggerDDTeamInfoLog(Database db) {
	state ReadYourWritesTransaction tr(db);
	loop {
		try {
			tr.setOption(FDBTransactionOptions::ACCESS_SYSTEM_KEYS);
			tr.setOption(FDBTransactionOptions::PRIORITY_SYSTEM_IMMEDIATE);
			std::string v = deterministicRandom()->randomUniqueID().toString();
			tr.set(triggerDDTeamInfoPrintKey, v);
			wait(tr.commit());
			printf("Triggered team info logging in data distribution.\n");
			return Void();
		} catch (Error& e) {
			wait(tr.onError(e));
		}
	}
}

ACTOR Future<Void> tssQuarantineList(Database db) {
	state ReadYourWritesTransaction tr(db);
	loop {
		try {
			tr.setOption(FDBTransactionOptions::ACCESS_SYSTEM_KEYS);
			tr.setOption(FDBTransactionOptions::PRIORITY_SYSTEM_IMMEDIATE);

			RangeResult result = wait(tr.getRange(tssQuarantineKeys, CLIENT_KNOBS->TOO_MANY));
			// shouldn't have many quarantined TSSes
			ASSERT(!result.more);
			printf("Found %d quarantined TSS processes%s\n", result.size(), result.size() == 0 ? "." : ":");
			for (auto& it : result) {
				printf("  %s\n", decodeTssQuarantineKey(it.key).toString().c_str());
			}
			return Void();
		} catch (Error& e) {
			wait(tr.onError(e));
		}
	}
}

ACTOR Future<bool> tssQuarantine(Database db, bool enable, UID tssId) {
	state Reference<ReadYourWritesTransaction> tr = makeReference<ReadYourWritesTransaction>(db);
	state KeyBackedMap<UID, UID> tssMapDB = KeyBackedMap<UID, UID>(tssMappingKeys.begin);

	loop {
		try {
			tr->setOption(FDBTransactionOptions::ACCESS_SYSTEM_KEYS);
			tr->setOption(FDBTransactionOptions::PRIORITY_SYSTEM_IMMEDIATE);

			// Do some validation first to make sure the command is valid
			Optional<Value> serverListValue = wait(tr->get(serverListKeyFor(tssId)));
			if (!serverListValue.present()) {
				printf("No TSS %s found in cluster!\n", tssId.toString().c_str());
				return false;
			}
			state StorageServerInterface ssi = decodeServerListValue(serverListValue.get());
			if (!ssi.isTss()) {
				printf("Cannot quarantine Non-TSS storage ID %s!\n", tssId.toString().c_str());
				return false;
			}

			Optional<Value> currentQuarantineValue = wait(tr->get(tssQuarantineKeyFor(tssId)));
			if (enable && currentQuarantineValue.present()) {
				printf("TSS %s already in quarantine, doing nothing.\n", tssId.toString().c_str());
				return false;
			} else if (!enable && !currentQuarantineValue.present()) {
				printf("TSS %s is not in quarantine, cannot remove from quarantine!.\n", tssId.toString().c_str());
				return false;
			}

			if (enable) {
				tr->set(tssQuarantineKeyFor(tssId), LiteralStringRef(""));
				// remove server from TSS mapping when quarantine is enabled
				tssMapDB.erase(tr, ssi.tssPairID.get());
			} else {
				tr->clear(tssQuarantineKeyFor(tssId));
			}

			wait(tr->commit());
			break;
		} catch (Error& e) {
			wait(tr->onError(e));
		}
	}
	printf("Successfully %s TSS %s\n", enable ? "quarantined" : "removed", tssId.toString().c_str());
	return true;
}

ACTOR Future<Void> timeWarning(double when, const char* msg) {
	wait(delay(when));
	fputs(msg, stderr);

	return Void();
}

ACTOR Future<Void> checkStatus(Future<Void> f, Database db, bool displayDatabaseAvailable = true) {
	wait(f);
	StatusObject s = wait(StatusClient::statusFetcher(db));
	printf("\n");
	printStatus(s, StatusClient::MINIMAL, displayDatabaseAvailable);
	printf("\n");
	return Void();
}

ACTOR template <class T>
Future<T> makeInterruptable(Future<T> f) {
	Future<Void> interrupt = LineNoise::onKeyboardInterrupt();
	choose {
		when(T t = wait(f)) { return t; }
		when(wait(interrupt)) {
			f.cancel();
			throw operation_cancelled();
		}
	}
}

ACTOR Future<Void> commitTransaction(Reference<ReadYourWritesTransaction> tr) {
	wait(makeInterruptable(tr->commit()));
	auto ver = tr->getCommittedVersion();
	if (ver != invalidVersion)
		printf("Committed (%" PRId64 ")\n", ver);
	else
		printf("Nothing to commit\n");
	return Void();
}

ACTOR Future<bool> configure(Database db,
                             std::vector<StringRef> tokens,
                             Reference<ClusterConnectionFile> ccf,
                             LineNoise* linenoise,
                             Future<Void> warn) {
	state ConfigurationResult result;
	state int startToken = 1;
	state bool force = false;
	if (tokens.size() < 2)
		result = ConfigurationResult::NO_OPTIONS_PROVIDED;
	else {
		if (tokens[startToken] == LiteralStringRef("FORCE")) {
			force = true;
			startToken = 2;
		}

		state Optional<ConfigureAutoResult> conf;
		if (tokens[startToken] == LiteralStringRef("auto")) {
			StatusObject s = wait(makeInterruptable(StatusClient::statusFetcher(db)));
			if (warn.isValid())
				warn.cancel();

			conf = parseConfig(s);

			if (!conf.get().isValid()) {
				printf("Unable to provide advice for the current configuration.\n");
				return true;
			}

			bool noChanges = conf.get().old_replication == conf.get().auto_replication &&
			                 conf.get().old_logs == conf.get().auto_logs &&
			                 conf.get().old_commit_proxies == conf.get().auto_commit_proxies &&
			                 conf.get().old_grv_proxies == conf.get().auto_grv_proxies &&
			                 conf.get().old_resolvers == conf.get().auto_resolvers &&
			                 conf.get().old_processes_with_transaction == conf.get().auto_processes_with_transaction &&
			                 conf.get().old_machines_with_transaction == conf.get().auto_machines_with_transaction;

			bool noDesiredChanges = noChanges && conf.get().old_logs == conf.get().desired_logs &&
			                        conf.get().old_commit_proxies == conf.get().desired_commit_proxies &&
			                        conf.get().old_grv_proxies == conf.get().desired_grv_proxies &&
			                        conf.get().old_resolvers == conf.get().desired_resolvers;

			std::string outputString;

			outputString += "\nYour cluster has:\n\n";
			outputString += format("  processes %d\n", conf.get().processes);
			outputString += format("  machines  %d\n", conf.get().machines);

			if (noDesiredChanges)
				outputString += "\nConfigure recommends keeping your current configuration:\n\n";
			else if (noChanges)
				outputString +=
				    "\nConfigure cannot modify the configuration because some parameters have been set manually:\n\n";
			else
				outputString += "\nConfigure recommends the following changes:\n\n";
			outputString += " ------------------------------------------------------------------- \n";
			outputString += "| parameter                   | old              | new              |\n";
			outputString += " ------------------------------------------------------------------- \n";
			outputString += format("| replication                 | %16s | %16s |\n",
			                       conf.get().old_replication.c_str(),
			                       conf.get().auto_replication.c_str());
			outputString +=
			    format("| logs                        | %16d | %16d |", conf.get().old_logs, conf.get().auto_logs);
			outputString += conf.get().auto_logs != conf.get().desired_logs
			                    ? format(" (manually set; would be %d)\n", conf.get().desired_logs)
			                    : "\n";
			outputString += format("| commit_proxies              | %16d | %16d |",
			                       conf.get().old_commit_proxies,
			                       conf.get().auto_commit_proxies);
			outputString += conf.get().auto_commit_proxies != conf.get().desired_commit_proxies
			                    ? format(" (manually set; would be %d)\n", conf.get().desired_commit_proxies)
			                    : "\n";
			outputString += format("| grv_proxies                 | %16d | %16d |",
			                       conf.get().old_grv_proxies,
			                       conf.get().auto_grv_proxies);
			outputString += conf.get().auto_grv_proxies != conf.get().desired_grv_proxies
			                    ? format(" (manually set; would be %d)\n", conf.get().desired_grv_proxies)
			                    : "\n";
			outputString += format(
			    "| resolvers                   | %16d | %16d |", conf.get().old_resolvers, conf.get().auto_resolvers);
			outputString += conf.get().auto_resolvers != conf.get().desired_resolvers
			                    ? format(" (manually set; would be %d)\n", conf.get().desired_resolvers)
			                    : "\n";
			outputString += format("| transaction-class processes | %16d | %16d |\n",
			                       conf.get().old_processes_with_transaction,
			                       conf.get().auto_processes_with_transaction);
			outputString += format("| transaction-class machines  | %16d | %16d |\n",
			                       conf.get().old_machines_with_transaction,
			                       conf.get().auto_machines_with_transaction);
			outputString += " ------------------------------------------------------------------- \n\n";

			std::printf("%s", outputString.c_str());

			if (noChanges)
				return false;

			// TODO: disable completion
			Optional<std::string> line = wait(linenoise->read("Would you like to make these changes? [y/n]> "));

			if (!line.present() || (line.get() != "y" && line.get() != "Y")) {
				return false;
			}
		}

		ConfigurationResult r = wait(makeInterruptable(
		    changeConfig(db, std::vector<StringRef>(tokens.begin() + startToken, tokens.end()), conf, force)));
		result = r;
	}

	// Real errors get thrown from makeInterruptable and printed by the catch block in cli(), but
	// there are various results specific to changeConfig() that we need to report:
	bool ret;
	switch (result) {
	case ConfigurationResult::NO_OPTIONS_PROVIDED:
	case ConfigurationResult::CONFLICTING_OPTIONS:
	case ConfigurationResult::UNKNOWN_OPTION:
	case ConfigurationResult::INCOMPLETE_CONFIGURATION:
		printUsage(LiteralStringRef("configure"));
		ret = true;
		break;
	case ConfigurationResult::INVALID_CONFIGURATION:
		fprintf(stderr, "ERROR: These changes would make the configuration invalid\n");
		ret = true;
		break;
	case ConfigurationResult::DATABASE_ALREADY_CREATED:
		fprintf(stderr, "ERROR: Database already exists! To change configuration, don't say `new'\n");
		ret = true;
		break;
	case ConfigurationResult::DATABASE_CREATED:
		printf("Database created\n");
		ret = false;
		break;
	case ConfigurationResult::DATABASE_UNAVAILABLE:
		fprintf(stderr, "ERROR: The database is unavailable\n");
		fprintf(stderr, "Type `configure FORCE <TOKEN...>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::STORAGE_IN_UNKNOWN_DCID:
		fprintf(stderr, "ERROR: All storage servers must be in one of the known regions\n");
		fprintf(stderr, "Type `configure FORCE <TOKEN...>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::REGION_NOT_FULLY_REPLICATED:
		fprintf(stderr,
		        "ERROR: When usable_regions > 1, all regions with priority >= 0 must be fully replicated "
		        "before changing the configuration\n");
		fprintf(stderr, "Type `configure FORCE <TOKEN...>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::MULTIPLE_ACTIVE_REGIONS:
		fprintf(stderr, "ERROR: When changing usable_regions, only one region can have priority >= 0\n");
		fprintf(stderr, "Type `configure FORCE <TOKEN...>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::REGIONS_CHANGED:
		fprintf(stderr,
		        "ERROR: The region configuration cannot be changed while simultaneously changing usable_regions\n");
		fprintf(stderr, "Type `configure FORCE <TOKEN...>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::NOT_ENOUGH_WORKERS:
		fprintf(stderr, "ERROR: Not enough processes exist to support the specified configuration\n");
		fprintf(stderr, "Type `configure FORCE <TOKEN...>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::REGION_REPLICATION_MISMATCH:
		fprintf(stderr, "ERROR: `three_datacenter' replication is incompatible with region configuration\n");
		fprintf(stderr, "Type `configure FORCE <TOKEN...>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::DCID_MISSING:
		fprintf(stderr, "ERROR: `No storage servers in one of the specified regions\n");
		fprintf(stderr, "Type `configure FORCE <TOKEN...>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::SUCCESS:
		printf("Configuration changed\n");
		ret = false;
		break;
	case ConfigurationResult::LOCKED_NOT_NEW:
		fprintf(stderr, "ERROR: `only new databases can be configured as locked`\n");
		ret = true;
		break;
	default:
		ASSERT(false);
		ret = true;
	};
	return ret;
}

ACTOR Future<bool> fileConfigure(Database db, std::string filePath, bool isNewDatabase, bool force) {
	std::string contents(readFileBytes(filePath, 100000));
	json_spirit::mValue config;
	if (!json_spirit::read_string(contents, config)) {
		fprintf(stderr, "ERROR: Invalid JSON\n");
		return true;
	}
	if (config.type() != json_spirit::obj_type) {
		fprintf(stderr, "ERROR: Configuration file must contain a JSON object\n");
		return true;
	}
	StatusObject configJSON = config.get_obj();

	json_spirit::mValue schema;
	if (!json_spirit::read_string(JSONSchemas::clusterConfigurationSchema.toString(), schema)) {
		ASSERT(false);
	}

	std::string errorStr;
	if (!schemaMatch(schema.get_obj(), configJSON, errorStr)) {
		printf("%s", errorStr.c_str());
		return true;
	}

	std::string configString;
	if (isNewDatabase) {
		configString = "new";
	}

	for (const auto& [name, value] : configJSON) {
		if (!configString.empty()) {
			configString += " ";
		}
		if (value.type() == json_spirit::int_type) {
			configString += name + ":=" + format("%d", value.get_int());
		} else if (value.type() == json_spirit::str_type) {
			configString += value.get_str();
		} else if (value.type() == json_spirit::array_type) {
			configString +=
			    name + "=" +
			    json_spirit::write_string(json_spirit::mValue(value.get_array()), json_spirit::Output_options::none);
		} else {
			printUsage(LiteralStringRef("fileconfigure"));
			return true;
		}
	}
	ConfigurationResult result = wait(makeInterruptable(changeConfig(db, configString, force)));
	// Real errors get thrown from makeInterruptable and printed by the catch block in cli(), but
	// there are various results specific to changeConfig() that we need to report:
	bool ret;
	switch (result) {
	case ConfigurationResult::NO_OPTIONS_PROVIDED:
		fprintf(stderr, "ERROR: No options provided\n");
		ret = true;
		break;
	case ConfigurationResult::CONFLICTING_OPTIONS:
		fprintf(stderr, "ERROR: Conflicting options\n");
		ret = true;
		break;
	case ConfigurationResult::UNKNOWN_OPTION:
		fprintf(stderr, "ERROR: Unknown option\n"); // This should not be possible because of schema match
		ret = true;
		break;
	case ConfigurationResult::INCOMPLETE_CONFIGURATION:
		fprintf(stderr,
		        "ERROR: Must specify both a replication level and a storage engine when creating a new database\n");
		ret = true;
		break;
	case ConfigurationResult::INVALID_CONFIGURATION:
		fprintf(stderr, "ERROR: These changes would make the configuration invalid\n");
		ret = true;
		break;
	case ConfigurationResult::DATABASE_ALREADY_CREATED:
		fprintf(stderr, "ERROR: Database already exists! To change configuration, don't say `new'\n");
		ret = true;
		break;
	case ConfigurationResult::DATABASE_CREATED:
		printf("Database created\n");
		ret = false;
		break;
	case ConfigurationResult::DATABASE_UNAVAILABLE:
		fprintf(stderr, "ERROR: The database is unavailable\n");
		printf("Type `fileconfigure FORCE <FILENAME>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::STORAGE_IN_UNKNOWN_DCID:
		fprintf(stderr, "ERROR: All storage servers must be in one of the known regions\n");
		printf("Type `fileconfigure FORCE <FILENAME>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::REGION_NOT_FULLY_REPLICATED:
		fprintf(stderr,
		        "ERROR: When usable_regions > 1, All regions with priority >= 0 must be fully replicated "
		        "before changing the configuration\n");
		printf("Type `fileconfigure FORCE <FILENAME>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::MULTIPLE_ACTIVE_REGIONS:
		fprintf(stderr, "ERROR: When changing usable_regions, only one region can have priority >= 0\n");
		printf("Type `fileconfigure FORCE <FILENAME>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::REGIONS_CHANGED:
		fprintf(stderr,
		        "ERROR: The region configuration cannot be changed while simultaneously changing usable_regions\n");
		printf("Type `fileconfigure FORCE <FILENAME>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::NOT_ENOUGH_WORKERS:
		fprintf(stderr, "ERROR: Not enough processes exist to support the specified configuration\n");
		printf("Type `fileconfigure FORCE <FILENAME>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::REGION_REPLICATION_MISMATCH:
		fprintf(stderr, "ERROR: `three_datacenter' replication is incompatible with region configuration\n");
		printf("Type `fileconfigure FORCE <TOKEN...>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::DCID_MISSING:
		fprintf(stderr, "ERROR: `No storage servers in one of the specified regions\n");
		printf("Type `fileconfigure FORCE <TOKEN...>' to configure without this check\n");
		ret = true;
		break;
	case ConfigurationResult::SUCCESS:
		printf("Configuration changed\n");
		ret = false;
		break;
	default:
		ASSERT(false);
		ret = true;
	};
	return ret;
}

// FIXME: Factor address parsing from coordinators, include, exclude

ACTOR Future<bool> coordinators(Database db, std::vector<StringRef> tokens, bool isClusterTLS) {
	state StringRef setName;
	StringRef nameTokenBegin = LiteralStringRef("description=");
	for (auto tok = tokens.begin() + 1; tok != tokens.end(); ++tok)
		if (tok->startsWith(nameTokenBegin)) {
			setName = tok->substr(nameTokenBegin.size());
			std::copy(tok + 1, tokens.end(), tok);
			tokens.resize(tokens.size() - 1);
			break;
		}

	bool automatic = tokens.size() == 2 && tokens[1] == LiteralStringRef("auto");

	state Reference<IQuorumChange> change;
	if (tokens.size() == 1 && setName.size()) {
		change = noQuorumChange();
	} else if (automatic) {
		// Automatic quorum change
		change = autoQuorumChange();
	} else {
		state std::set<NetworkAddress> addresses;
		state std::vector<StringRef>::iterator t;
		for (t = tokens.begin() + 1; t != tokens.end(); ++t) {
			try {
				// SOMEDAY: Check for keywords
				auto const& addr = NetworkAddress::parse(t->toString());
				if (addresses.count(addr)) {
					fprintf(stderr, "ERROR: passed redundant coordinators: `%s'\n", addr.toString().c_str());
					return true;
				}
				addresses.insert(addr);
			} catch (Error& e) {
				if (e.code() == error_code_connection_string_invalid) {
					fprintf(stderr, "ERROR: '%s' is not a valid network endpoint address\n", t->toString().c_str());
					return true;
				}
				throw;
			}
		}

		std::vector<NetworkAddress> addressesVec(addresses.begin(), addresses.end());
		change = specifiedQuorumChange(addressesVec);
	}
	if (setName.size())
		change = nameQuorumChange(setName.toString(), change);

	CoordinatorsResult r = wait(makeInterruptable(changeQuorum(db, change)));

	// Real errors get thrown from makeInterruptable and printed by the catch block in cli(), but
	// there are various results specific to changeConfig() that we need to report:
	bool err = true;
	switch (r) {
	case CoordinatorsResult::INVALID_NETWORK_ADDRESSES:
		fprintf(stderr, "ERROR: The specified network addresses are invalid\n");
		break;
	case CoordinatorsResult::SAME_NETWORK_ADDRESSES:
		printf("No change (existing configuration satisfies request)\n");
		err = false;
		break;
	case CoordinatorsResult::NOT_COORDINATORS:
		fprintf(stderr, "ERROR: Coordination servers are not running on the specified network addresses\n");
		break;
	case CoordinatorsResult::DATABASE_UNREACHABLE:
		fprintf(stderr, "ERROR: Database unreachable\n");
		break;
	case CoordinatorsResult::BAD_DATABASE_STATE:
		fprintf(stderr,
		        "ERROR: The database is in an unexpected state from which changing coordinators might be unsafe\n");
		break;
	case CoordinatorsResult::COORDINATOR_UNREACHABLE:
		fprintf(stderr, "ERROR: One of the specified coordinators is unreachable\n");
		break;
	case CoordinatorsResult::SUCCESS:
		printf("Coordination state changed\n");
		err = false;
		break;
	case CoordinatorsResult::NOT_ENOUGH_MACHINES:
		fprintf(stderr, "ERROR: Too few fdbserver machines to provide coordination at the current redundancy level\n");
		break;
	default:
		ASSERT(false);
	};
	return err;
}

// Includes the servers that could be IP addresses or localities back to the cluster.
ACTOR Future<bool> include(Database db, std::vector<StringRef> tokens) {
	std::vector<AddressExclusion> addresses;
	state std::vector<std::string> localities;
	state bool failed = false;
	state bool all = false;
	for (auto t = tokens.begin() + 1; t != tokens.end(); ++t) {
		if (*t == LiteralStringRef("all")) {
			all = true;
		} else if (*t == LiteralStringRef("failed")) {
			failed = true;
		} else if (t->startsWith(LocalityData::ExcludeLocalityPrefix) && t->toString().find(':') != std::string::npos) {
			// if the token starts with 'locality_' prefix.
			localities.push_back(t->toString());
		} else {
			auto a = AddressExclusion::parse(*t);
			if (!a.isValid()) {
				fprintf(stderr,
				        "ERROR: '%s' is neither a valid network endpoint address nor a locality\n",
				        t->toString().c_str());
				if (t->toString().find(":tls") != std::string::npos)
					printf("        Do not include the `:tls' suffix when naming a process\n");
				return true;
			}
			addresses.push_back(a);
		}
	}
	if (all) {
		std::vector<AddressExclusion> includeAll;
		includeAll.push_back(AddressExclusion());
		wait(makeInterruptable(includeServers(db, includeAll, failed)));
		wait(makeInterruptable(includeLocalities(db, localities, failed, all)));
	} else {
		if (!addresses.empty()) {
			wait(makeInterruptable(includeServers(db, addresses, failed)));
		}
		if (!localities.empty()) {
			// includes the servers that belong to given localities.
			wait(makeInterruptable(includeLocalities(db, localities, failed, all)));
		}
	}
	return false;
};

ACTOR Future<bool> exclude(Database db,
                           std::vector<StringRef> tokens,
                           Reference<ClusterConnectionFile> ccf,
                           Future<Void> warn) {
	if (tokens.size() <= 1) {
		state Future<vector<AddressExclusion>> fexclAddresses = makeInterruptable(getExcludedServers(db));
		state Future<vector<std::string>> fexclLocalities = makeInterruptable(getExcludedLocalities(db));

		wait(success(fexclAddresses) && success(fexclLocalities));
		vector<AddressExclusion> exclAddresses = fexclAddresses.get();
		vector<std::string> exclLocalities = fexclLocalities.get();

		if (!exclAddresses.size() && !exclLocalities.size()) {
			printf("There are currently no servers or localities excluded from the database.\n"
			       "To learn how to exclude a server, type `help exclude'.\n");
			return false;
		}

		printf("There are currently %zu servers or localities being excluded from the database:\n",
		       exclAddresses.size() + exclLocalities.size());
		for (const auto& e : exclAddresses)
			printf("  %s\n", e.toString().c_str());
		for (const auto& e : exclLocalities)
			printf("  %s\n", e.c_str());

		printf("To find out whether it is safe to remove one or more of these\n"
		       "servers from the cluster, type `exclude <addresses>'.\n"
		       "To return one of these servers to the cluster, type `include <addresses>'.\n");

		return false;
	} else {
		state std::vector<AddressExclusion> exclusionVector;
		state std::set<AddressExclusion> exclusionSet;
		state std::vector<AddressExclusion> exclusionAddresses;
		state std::unordered_set<std::string> exclusionLocalities;
		state std::vector<std::string> noMatchLocalities;
		state bool force = false;
		state bool waitForAllExcluded = true;
		state bool markFailed = false;
		state std::vector<ProcessData> workers = wait(makeInterruptable(getWorkers(db)));
		for (auto t = tokens.begin() + 1; t != tokens.end(); ++t) {
			if (*t == LiteralStringRef("FORCE")) {
				force = true;
			} else if (*t == LiteralStringRef("no_wait")) {
				waitForAllExcluded = false;
			} else if (*t == LiteralStringRef("failed")) {
				markFailed = true;
			} else if (t->startsWith(LocalityData::ExcludeLocalityPrefix) &&
			           t->toString().find(':') != std::string::npos) {
				std::set<AddressExclusion> localityAddresses = getAddressesByLocality(workers, t->toString());
				if (localityAddresses.empty()) {
					noMatchLocalities.push_back(t->toString());
				} else {
					// add all the server ipaddresses that belong to the given localities to the exclusionSet.
					exclusionVector.insert(exclusionVector.end(), localityAddresses.begin(), localityAddresses.end());
					exclusionSet.insert(localityAddresses.begin(), localityAddresses.end());
				}
				exclusionLocalities.insert(t->toString());
			} else {
				auto a = AddressExclusion::parse(*t);
				if (!a.isValid()) {
					fprintf(stderr,
					        "ERROR: '%s' is neither a valid network endpoint address nor a locality\n",
					        t->toString().c_str());
					if (t->toString().find(":tls") != std::string::npos)
						printf("        Do not include the `:tls' suffix when naming a process\n");
					return true;
				}
				exclusionVector.push_back(a);
				exclusionSet.insert(a);
				exclusionAddresses.push_back(a);
			}
		}

		if (exclusionAddresses.empty() && exclusionLocalities.empty()) {
			fprintf(stderr, "ERROR: At least one valid network endpoint address or a locality is not provided\n");
			return true;
		}

		if (!force) {
			if (markFailed) {
				state bool safe;
				try {
					bool _safe = wait(makeInterruptable(checkSafeExclusions(db, exclusionVector)));
					safe = _safe;
				} catch (Error& e) {
					if (e.code() == error_code_actor_cancelled)
						throw;
					TraceEvent("CheckSafeExclusionsError").error(e);
					safe = false;
				}
				if (!safe) {
					std::string errorStr =
					    "ERROR: It is unsafe to exclude the specified servers at this time.\n"
					    "Please check that this exclusion does not bring down an entire storage team.\n"
					    "Please also ensure that the exclusion will keep a majority of coordinators alive.\n"
					    "You may add more storage processes or coordinators to make the operation safe.\n"
					    "Type `exclude FORCE failed <ADDRESS...>' to exclude without performing safety checks.\n";
					printf("%s", errorStr.c_str());
					return true;
				}
			}
			StatusObject status = wait(makeInterruptable(StatusClient::statusFetcher(db)));

			state std::string errorString =
			    "ERROR: Could not calculate the impact of this exclude on the total free space in the cluster.\n"
			    "Please try the exclude again in 30 seconds.\n"
			    "Type `exclude FORCE <ADDRESS...>' to exclude without checking free space.\n";

			StatusObjectReader statusObj(status);

			StatusObjectReader statusObjCluster;
			if (!statusObj.get("cluster", statusObjCluster)) {
				fprintf(stderr, "%s", errorString.c_str());
				return true;
			}

			StatusObjectReader processesMap;
			if (!statusObjCluster.get("processes", processesMap)) {
				fprintf(stderr, "%s", errorString.c_str());
				return true;
			}

			state int ssTotalCount = 0;
			state int ssExcludedCount = 0;
			state double worstFreeSpaceRatio = 1.0;
			try {
				for (auto proc : processesMap.obj()) {
					bool storageServer = false;
					StatusArray rolesArray = proc.second.get_obj()["roles"].get_array();
					for (StatusObjectReader role : rolesArray) {
						if (role["role"].get_str() == "storage") {
							storageServer = true;
							break;
						}
					}
					// Skip non-storage servers in free space calculation
					if (!storageServer)
						continue;

					StatusObjectReader process(proc.second);
					std::string addrStr;
					if (!process.get("address", addrStr)) {
						fprintf(stderr, "%s", errorString.c_str());
						return true;
					}
					NetworkAddress addr = NetworkAddress::parse(addrStr);
					bool excluded =
					    (process.has("excluded") && process.last().get_bool()) || addressExcluded(exclusionSet, addr);
					ssTotalCount++;
					if (excluded)
						ssExcludedCount++;

					if (!excluded) {
						StatusObjectReader disk;
						if (!process.get("disk", disk)) {
							fprintf(stderr, "%s", errorString.c_str());
							return true;
						}

						int64_t total_bytes;
						if (!disk.get("total_bytes", total_bytes)) {
							fprintf(stderr, "%s", errorString.c_str());
							return true;
						}

						int64_t free_bytes;
						if (!disk.get("free_bytes", free_bytes)) {
							fprintf(stderr, "%s", errorString.c_str());
							return true;
						}

						worstFreeSpaceRatio = std::min(worstFreeSpaceRatio, double(free_bytes) / total_bytes);
					}
				}
			} catch (...) // std::exception
			{
				fprintf(stderr, "%s", errorString.c_str());
				return true;
			}

			if (ssExcludedCount == ssTotalCount ||
			    (1 - worstFreeSpaceRatio) * ssTotalCount / (ssTotalCount - ssExcludedCount) > 0.9) {
				fprintf(stderr,
				        "ERROR: This exclude may cause the total free space in the cluster to drop below 10%%.\n"
				        "Type `exclude FORCE <ADDRESS...>' to exclude without checking free space.\n");
				return true;
			}
		}

		if (!exclusionAddresses.empty()) {
			wait(makeInterruptable(excludeServers(db, exclusionAddresses, markFailed)));
		}
		if (!exclusionLocalities.empty()) {
			wait(makeInterruptable(excludeLocalities(db, exclusionLocalities, markFailed)));
		}

		if (waitForAllExcluded) {
			printf("Waiting for state to be removed from all excluded servers. This may take a while.\n");
			printf("(Interrupting this wait with CTRL+C will not cancel the data movement.)\n");
		}

		if (warn.isValid())
			warn.cancel();

		state std::set<NetworkAddress> notExcludedServers =
		    wait(makeInterruptable(checkForExcludingServers(db, exclusionVector, waitForAllExcluded)));
		std::map<IPAddress, std::set<uint16_t>> workerPorts;
		for (auto addr : workers)
			workerPorts[addr.address.ip].insert(addr.address.port);

		// Print a list of all excluded addresses that don't have a corresponding worker
		std::set<AddressExclusion> absentExclusions;
		for (const auto& addr : exclusionVector) {
			auto worker = workerPorts.find(addr.ip);
			if (worker == workerPorts.end())
				absentExclusions.insert(addr);
			else if (addr.port > 0 && worker->second.count(addr.port) == 0)
				absentExclusions.insert(addr);
		}

		for (const auto& exclusion : exclusionVector) {
			if (absentExclusions.find(exclusion) != absentExclusions.end()) {
				if (exclusion.port == 0) {
					fprintf(stderr,
					        "  %s(Whole machine)  ---- WARNING: Missing from cluster!Be sure that you excluded the "
					        "correct machines before removing them from the cluster!\n",
					        exclusion.ip.toString().c_str());
				} else {
					fprintf(stderr,
					        "  %s  ---- WARNING: Missing from cluster! Be sure that you excluded the correct processes "
					        "before removing them from the cluster!\n",
					        exclusion.toString().c_str());
				}
			} else if (std::any_of(notExcludedServers.begin(), notExcludedServers.end(), [&](const NetworkAddress& a) {
				           return addressExcluded({ exclusion }, a);
			           })) {
				if (exclusion.port == 0) {
					fprintf(stderr,
					        "  %s(Whole machine)  ---- WARNING: Exclusion in progress! It is not safe to remove this "
					        "machine from the cluster\n",
					        exclusion.ip.toString().c_str());
				} else {
					fprintf(stderr,
					        "  %s  ---- WARNING: Exclusion in progress! It is not safe to remove this process from the "
					        "cluster\n",
					        exclusion.toString().c_str());
				}
			} else {
				if (exclusion.port == 0) {
					printf("  %s(Whole machine)  ---- Successfully excluded. It is now safe to remove this machine "
					       "from the cluster.\n",
					       exclusion.ip.toString().c_str());
				} else {
					printf(
					    "  %s  ---- Successfully excluded. It is now safe to remove this process from the cluster.\n",
					    exclusion.toString().c_str());
				}
			}
		}

		for (const auto& locality : noMatchLocalities) {
			fprintf(
			    stderr,
			    "  %s  ---- WARNING: Currently no servers found with this locality match! Be sure that you excluded "
			    "the correct locality.\n",
			    locality.c_str());
		}

		bool foundCoordinator = false;
		auto ccs = ClusterConnectionFile(ccf->getFilename()).getConnectionString();
		for (const auto& c : ccs.coordinators()) {
			if (std::count(exclusionVector.begin(), exclusionVector.end(), AddressExclusion(c.ip, c.port)) ||
			    std::count(exclusionVector.begin(), exclusionVector.end(), AddressExclusion(c.ip))) {
				fprintf(stderr, "WARNING: %s is a coordinator!\n", c.toString().c_str());
				foundCoordinator = true;
			}
		}
		if (foundCoordinator)
			printf("Type `help coordinators' for information on how to change the\n"
			       "cluster's coordination servers before removing them.\n");

		return false;
	}
}

ACTOR Future<bool> createSnapshot(Database db, std::vector<StringRef> tokens) {
	state Standalone<StringRef> snapCmd;
	state UID snapUID = deterministicRandom()->randomUniqueID();
	for (int i = 1; i < tokens.size(); i++) {
		snapCmd = snapCmd.withSuffix(tokens[i]);
		if (i != tokens.size() - 1) {
			snapCmd = snapCmd.withSuffix(LiteralStringRef(" "));
		}
	}
	try {
		wait(makeInterruptable(mgmtSnapCreate(db, snapCmd, snapUID)));
		printf("Snapshot command succeeded with UID %s\n", snapUID.toString().c_str());
	} catch (Error& e) {
		fprintf(stderr,
		        "Snapshot command failed %d (%s)."
		        " Please cleanup any instance level snapshots created with UID %s.\n",
		        e.code(),
		        e.what(),
		        snapUID.toString().c_str());
		return true;
	}
	return false;
}

Reference<ReadYourWritesTransaction> getTransaction(Database db,
                                                    Reference<ReadYourWritesTransaction>& tr,
                                                    FdbOptions* options,
                                                    bool intrans) {
	if (!tr || !intrans) {
		tr = makeReference<ReadYourWritesTransaction>(db);
		options->apply(tr);
	}

	return tr;
}

// TODO: Update the function to get rid of Database and ReadYourWritesTransaction after refactoring
// The original ReadYourWritesTransaciton handle "tr" is needed as some commands can be called inside a
// transaction and "tr" holds the pointer to the ongoing transaction object. As it's not easy to get ride of "tr" in
// one shot and we are refactoring the code to use Reference<ITransaction> (tr2), we need to let "tr2" point to the same
// underlying transaction like "tr". Thus everytime we need to use "tr2",  we first update "tr" and let "tr2" points to
// "tr1". "tr2" is always having the same lifetime as "tr1"
Reference<ITransaction> getTransaction(Database db,
                                       Reference<ReadYourWritesTransaction>& tr,
                                       Reference<ITransaction>& tr2,
                                       FdbOptions* options,
                                       bool intrans) {
	// Update "tr" to point to a brand new transaction object when it's not initialized or "intrans" flag is "false",
	// which indicates we need a new transaction object
	if (!tr || !intrans) {
		tr = makeReference<ReadYourWritesTransaction>(db);
		options->apply(tr);
	}
	tr2 = Reference<ITransaction>(new ThreadSafeTransaction(tr.getPtr()));
	return tr2;
}

std::string newCompletion(const char* base, const char* name) {
	return format("%s%s ", base, name);
}

void compGenerator(const char* text, bool help, std::vector<std::string>& lc) {
	std::map<std::string, CommandHelp>::const_iterator iter;
	int len = strlen(text);

	const char* helpExtra[] = { "escaping", "options", nullptr };

	const char** he = helpExtra;

	for (auto iter = helpMap.begin(); iter != helpMap.end(); ++iter) {
		const char* name = (*iter).first.c_str();
		if (!strncmp(name, text, len)) {
			lc.push_back(newCompletion(help ? "help " : "", name));
		}
	}

	if (help) {
		while (*he) {
			const char* name = *he;
			he++;
			if (!strncmp(name, text, len))
				lc.push_back(newCompletion("help ", name));
		}
	}
}

void cmdGenerator(const char* text, std::vector<std::string>& lc) {
	compGenerator(text, false, lc);
}

void helpGenerator(const char* text, std::vector<std::string>& lc) {
	compGenerator(text, true, lc);
}

void optionGenerator(const char* text, const char* line, std::vector<std::string>& lc) {
	int len = strlen(text);

	for (auto iter = validOptions.begin(); iter != validOptions.end(); ++iter) {
		const char* name = (*iter).c_str();
		if (!strncmp(name, text, len)) {
			lc.push_back(newCompletion(line, name));
		}
	}
}

void arrayGenerator(const char* text, const char* line, const char** options, std::vector<std::string>& lc) {
	const char** iter = options;
	int len = strlen(text);

	while (*iter) {
		const char* name = *iter;
		iter++;
		if (!strncmp(name, text, len)) {
			lc.push_back(newCompletion(line, name));
		}
	}
}

void onOffGenerator(const char* text, const char* line, std::vector<std::string>& lc) {
	const char* opts[] = { "on", "off", nullptr };
	arrayGenerator(text, line, opts, lc);
}

void configureGenerator(const char* text, const char* line, std::vector<std::string>& lc) {
	const char* opts[] = { "new",
		                   "single",
		                   "double",
		                   "triple",
		                   "three_data_hall",
		                   "three_datacenter",
		                   "ssd",
		                   "ssd-1",
		                   "ssd-2",
		                   "memory",
		                   "memory-1",
		                   "memory-2",
		                   "memory-radixtree-beta",
		                   "commit_proxies=",
		                   "grv_proxies=",
		                   "logs=",
		                   "resolvers=",
		                   "perpetual_storage_wiggle=",
		                   nullptr };
	arrayGenerator(text, line, opts, lc);
}

void statusGenerator(const char* text, const char* line, std::vector<std::string>& lc) {
	const char* opts[] = { "minimal", "details", "json", nullptr };
	arrayGenerator(text, line, opts, lc);
}

void killGenerator(const char* text, const char* line, std::vector<std::string>& lc) {
	const char* opts[] = { "all", "list", nullptr };
	arrayGenerator(text, line, opts, lc);
}

void throttleGenerator(const char* text,
                       const char* line,
                       std::vector<std::string>& lc,
                       std::vector<StringRef> const& tokens) {
	if (tokens.size() == 1) {
		const char* opts[] = { "on tag", "off", "enable auto", "disable auto", "list", nullptr };
		arrayGenerator(text, line, opts, lc);
	} else if (tokens.size() >= 2 && tokencmp(tokens[1], "on")) {
		if (tokens.size() == 2) {
			const char* opts[] = { "tag", nullptr };
			arrayGenerator(text, line, opts, lc);
		} else if (tokens.size() == 6) {
			const char* opts[] = { "default", "immediate", "batch", nullptr };
			arrayGenerator(text, line, opts, lc);
		}
	} else if (tokens.size() >= 2 && tokencmp(tokens[1], "off") && !tokencmp(tokens[tokens.size() - 1], "tag")) {
		const char* opts[] = { "all", "auto", "manual", "tag", "default", "immediate", "batch", nullptr };
		arrayGenerator(text, line, opts, lc);
	} else if (tokens.size() == 2 && (tokencmp(tokens[1], "enable") || tokencmp(tokens[1], "disable"))) {
		const char* opts[] = { "auto", nullptr };
		arrayGenerator(text, line, opts, lc);
	} else if (tokens.size() >= 2 && tokencmp(tokens[1], "list")) {
		if (tokens.size() == 2) {
			const char* opts[] = { "throttled", "recommended", "all", nullptr };
			arrayGenerator(text, line, opts, lc);
		} else if (tokens.size() == 3) {
			const char* opts[] = { "LIMITS", nullptr };
			arrayGenerator(text, line, opts, lc);
		}
	}
}

void fdbcliCompCmd(std::string const& text, std::vector<std::string>& lc) {
	bool err, partial;
	std::string whole_line = text;
	auto parsed = parseLine(whole_line, err, partial);
	if (err || partial) // If there was an error, or we are partially through a quoted sequence
		return;

	auto tokens = parsed.back();
	int count = tokens.size();

	// for(int i = 0; i < count; i++) {
	// 	printf("Token (%d): `%s'\n", i, tokens[i].toString().c_str());
	// }

	std::string ntext = "";
	std::string base_input = text;

	// If there is a token and the input does not end in a space
	if (count && text.size() > 0 && text[text.size() - 1] != ' ') {
		count--; // Ignore the last token for purposes of later code
		ntext = tokens.back().toString();
		base_input = whole_line.substr(0, whole_line.rfind(ntext));
	}

	// printf("final text (%d tokens): `%s' & `%s'\n", count, base_input.c_str(), ntext.c_str());

	if (!count) {
		cmdGenerator(ntext.c_str(), lc);
		return;
	}

	if (tokencmp(tokens[0], "help") && count == 1) {
		helpGenerator(ntext.c_str(), lc);
		return;
	}

	if (tokencmp(tokens[0], "option")) {
		if (count == 1)
			onOffGenerator(ntext.c_str(), base_input.c_str(), lc);
		if (count == 2)
			optionGenerator(ntext.c_str(), base_input.c_str(), lc);
	}

	if (tokencmp(tokens[0], "writemode") && count == 1) {
		onOffGenerator(ntext.c_str(), base_input.c_str(), lc);
	}

	if (tokencmp(tokens[0], "configure")) {
		configureGenerator(ntext.c_str(), base_input.c_str(), lc);
	}

	if (tokencmp(tokens[0], "status") && count == 1) {
		statusGenerator(ntext.c_str(), base_input.c_str(), lc);
	}

	if (tokencmp(tokens[0], "kill") && count == 1) {
		killGenerator(ntext.c_str(), base_input.c_str(), lc);
	}

	if (tokencmp(tokens[0], "throttle")) {
		throttleGenerator(ntext.c_str(), base_input.c_str(), lc, tokens);
	}
}

std::vector<const char*> throttleHintGenerator(std::vector<StringRef> const& tokens, bool inArgument) {
	if (tokens.size() == 1) {
		return { "<on|off|enable auto|disable auto|list>", "[ARGS]" };
	} else if (tokencmp(tokens[1], "on")) {
		std::vector<const char*> opts = { "tag", "<TAG>", "[RATE]", "[DURATION]", "[default|immediate|batch]" };
		if (tokens.size() == 2) {
			return opts;
		} else if (((tokens.size() == 3 && inArgument) || tokencmp(tokens[2], "tag")) && tokens.size() < 7) {
			return std::vector<const char*>(opts.begin() + tokens.size() - 2, opts.end());
		}
	} else if (tokencmp(tokens[1], "off")) {
		if (tokencmp(tokens[tokens.size() - 1], "tag")) {
			return { "<TAG>" };
		} else {
			bool hasType = false;
			bool hasTag = false;
			bool hasPriority = false;
			for (int i = 2; i < tokens.size(); ++i) {
				if (tokencmp(tokens[i], "all") || tokencmp(tokens[i], "auto") || tokencmp(tokens[i], "manual")) {
					hasType = true;
				} else if (tokencmp(tokens[i], "default") || tokencmp(tokens[i], "immediate") ||
				           tokencmp(tokens[i], "batch")) {
					hasPriority = true;
				} else if (tokencmp(tokens[i], "tag")) {
					hasTag = true;
					++i;
				} else {
					return {};
				}
			}

			std::vector<const char*> options;
			if (!hasType) {
				options.push_back("[all|auto|manual]");
			}
			if (!hasTag) {
				options.push_back("[tag <TAG>]");
			}
			if (!hasPriority) {
				options.push_back("[default|immediate|batch]");
			}

			return options;
		}
	} else if ((tokencmp(tokens[1], "enable") || tokencmp(tokens[1], "disable")) && tokens.size() == 2) {
		return { "auto" };
	} else if (tokens.size() >= 2 && tokencmp(tokens[1], "list")) {
		if (tokens.size() == 2) {
			return { "[throttled|recommended|all]", "[LIMITS]" };
		} else if (tokens.size() == 3 && (tokencmp(tokens[2], "throttled") || tokencmp(tokens[2], "recommended") ||
		                                  tokencmp(tokens[2], "all"))) {
			return { "[LIMITS]" };
		}
	} else if (tokens.size() == 2 && inArgument) {
		return { "[ARGS]" };
	}

	return std::vector<const char*>();
}

void LogCommand(std::string line, UID randomID, std::string errMsg) {
	printf("%s\n", errMsg.c_str());
	TraceEvent(SevInfo, "CLICommandLog", randomID).detail("Command", line).detail("Error", errMsg);
}

struct CLIOptions {
	std::string program_name;
	int exit_code = -1;

	std::string commandLine;

	std::string clusterFile;
	bool trace = false;
	std::string traceDir;
	std::string traceFormat;
	int exit_timeout = 0;
	Optional<std::string> exec;
	bool initialStatusCheck = true;
	bool cliHints = true;
	bool debugTLS = false;
	std::string tlsCertPath;
	std::string tlsKeyPath;
	std::string tlsVerifyPeers;
	std::string tlsCAPath;
	std::string tlsPassword;

	std::vector<std::pair<std::string, std::string>> knobs;

	CLIOptions(int argc, char* argv[]) {
		program_name = argv[0];
		for (int a = 0; a < argc; a++) {
			if (a)
				commandLine += ' ';
			commandLine += argv[a];
		}

		CSimpleOpt args(argc, argv, g_rgOptions);

		while (args.Next()) {
			int ec = processArg(args);
			if (ec != -1) {
				exit_code = ec;
				return;
			}
		}
		if (exit_timeout && !exec.present()) {
			fprintf(stderr, "ERROR: --timeout may only be specified with --exec\n");
			exit_code = FDB_EXIT_ERROR;
			return;
		}

		auto& g_knobs = IKnobCollection::getMutableGlobalKnobCollection();
		for (const auto& [knobName, knobValueString] : knobs) {
			try {
				auto knobValue = g_knobs.parseKnobValue(knobName, knobValueString);
				g_knobs.setKnob(knobName, knobValue);
			} catch (Error& e) {
				if (e.code() == error_code_invalid_option_value) {
					fprintf(stderr,
					        "WARNING: Invalid value '%s' for knob option '%s'\n",
					        knobValueString.c_str(),
					        knobName.c_str());
					TraceEvent(SevWarnAlways, "InvalidKnobValue")
					    .detail("Knob", printable(knobName))
					    .detail("Value", printable(knobValueString));
				} else {
					fprintf(stderr, "ERROR: Failed to set knob option '%s': %s\n", knobName.c_str(), e.what());
					TraceEvent(SevError, "FailedToSetKnob")
					    .detail("Knob", printable(knobName))
					    .detail("Value", printable(knobValueString))
					    .error(e);
					exit_code = FDB_EXIT_ERROR;
				}
			}
		}

		// Reinitialize knobs in order to update knobs that are dependent on explicitly set knobs
		g_knobs.initialize(Randomize::False, IsSimulated::False);
	}

	int processArg(CSimpleOpt& args) {
		if (args.LastError() != SO_SUCCESS) {
			printProgramUsage(program_name.c_str());
			return 1;
		}

		switch (args.OptionId()) {
		case OPT_CONNFILE:
			clusterFile = args.OptionArg();
			break;
		case OPT_TRACE:
			trace = true;
			break;
		case OPT_TRACE_DIR:
			traceDir = args.OptionArg();
			break;
		case OPT_TIMEOUT: {
			char* endptr;
			exit_timeout = strtoul((char*)args.OptionArg(), &endptr, 10);
			if (*endptr != '\0') {
				fprintf(stderr, "ERROR: invalid timeout %s\n", args.OptionArg());
				return 1;
			}
			break;
		}
		case OPT_EXEC:
			exec = args.OptionArg();
			break;
		case OPT_NO_STATUS:
			initialStatusCheck = false;
			break;
		case OPT_NO_HINTS:
			cliHints = false;

#ifndef TLS_DISABLED
		// TLS Options
		case TLSConfig::OPT_TLS_PLUGIN:
			args.OptionArg();
			break;
		case TLSConfig::OPT_TLS_CERTIFICATES:
			tlsCertPath = args.OptionArg();
			break;
		case TLSConfig::OPT_TLS_CA_FILE:
			tlsCAPath = args.OptionArg();
			break;
		case TLSConfig::OPT_TLS_KEY:
			tlsKeyPath = args.OptionArg();
			break;
		case TLSConfig::OPT_TLS_PASSWORD:
			tlsPassword = args.OptionArg();
			break;
		case TLSConfig::OPT_TLS_VERIFY_PEERS:
			tlsVerifyPeers = args.OptionArg();
			break;
#endif
		case OPT_HELP:
			printProgramUsage(program_name.c_str());
			return 0;
		case OPT_STATUS_FROM_JSON:
			return printStatusFromJSON(args.OptionArg());
		case OPT_TRACE_FORMAT:
			if (!validateTraceFormat(args.OptionArg())) {
				fprintf(stderr, "WARNING: Unrecognized trace format `%s'\n", args.OptionArg());
			}
			traceFormat = args.OptionArg();
			break;
		case OPT_KNOB: {
			std::string syn = args.OptionSyntax();
			if (!StringRef(syn).startsWith(LiteralStringRef("--knob_"))) {
				fprintf(stderr, "ERROR: unable to parse knob option '%s'\n", syn.c_str());
				return FDB_EXIT_ERROR;
			}
			syn = syn.substr(7);
			knobs.emplace_back(syn, args.OptionArg());
			break;
		}
		case OPT_DEBUG_TLS:
			debugTLS = true;
			break;
		case OPT_VERSION:
			printVersion();
			return FDB_EXIT_SUCCESS;
		case OPT_BUILD_FLAGS:
			printBuildInformation();
			return FDB_EXIT_SUCCESS;
		}
		return -1;
	}
};

ACTOR template <class T>
Future<T> stopNetworkAfter(Future<T> what) {
	try {
		T t = wait(what);
		g_network->stop();
		return t;
	} catch (...) {
		g_network->stop();
		throw;
	}
}

ACTOR Future<Void> addInterface(std::map<Key, std::pair<Value, ClientLeaderRegInterface>>* address_interface,
                                Reference<FlowLock> connectLock,
                                KeyValue kv) {
	wait(connectLock->take());
	state FlowLock::Releaser releaser(*connectLock);
	state ClientWorkerInterface workerInterf =
	    BinaryReader::fromStringRef<ClientWorkerInterface>(kv.value, IncludeVersion());
	state ClientLeaderRegInterface leaderInterf(workerInterf.address());
	choose {
		when(Optional<LeaderInfo> rep =
		         wait(brokenPromiseToNever(leaderInterf.getLeader.getReply(GetLeaderRequest())))) {
			StringRef ip_port =
			    (kv.key.endsWith(LiteralStringRef(":tls")) ? kv.key.removeSuffix(LiteralStringRef(":tls")) : kv.key)
			        .removePrefix(LiteralStringRef("\xff\xff/worker_interfaces/"));
			(*address_interface)[ip_port] = std::make_pair(kv.value, leaderInterf);

			if (workerInterf.reboot.getEndpoint().addresses.secondaryAddress.present()) {
				Key full_ip_port2 =
				    StringRef(workerInterf.reboot.getEndpoint().addresses.secondaryAddress.get().toString());
				StringRef ip_port2 = full_ip_port2.endsWith(LiteralStringRef(":tls"))
				                         ? full_ip_port2.removeSuffix(LiteralStringRef(":tls"))
				                         : full_ip_port2;
				(*address_interface)[ip_port2] = std::make_pair(kv.value, leaderInterf);
			}
		}
		when(wait(delay(CLIENT_KNOBS->CLI_CONNECT_TIMEOUT))) {}
	}
	return Void();
}

ACTOR Future<int> cli(CLIOptions opt, LineNoise* plinenoise) {
	state LineNoise& linenoise = *plinenoise;
	state bool intrans = false;

	state Database db;
	state Reference<ReadYourWritesTransaction> tr;
	// TODO: refactoring work, will replace db, tr when we have all commands through the general fdb interface
	state Reference<IDatabase> db2;
	state Reference<ITransaction> tr2;

	state bool writeMode = false;

	state std::string clusterConnectString;
	state std::map<Key, std::pair<Value, ClientLeaderRegInterface>> address_interface;

	state FdbOptions globalOptions;
	state FdbOptions activeOptions;

	state FdbOptions* options = &globalOptions;

	state Reference<ClusterConnectionFile> ccf;

	state std::pair<std::string, bool> resolvedClusterFile =
	    ClusterConnectionFile::lookupClusterFileName(opt.clusterFile);
	try {
		ccf = makeReference<ClusterConnectionFile>(resolvedClusterFile.first);
	} catch (Error& e) {
		fprintf(stderr, "%s\n", ClusterConnectionFile::getErrorString(resolvedClusterFile, e).c_str());
		return 1;
	}

	// Ordinarily, this is done when the network is run. However, network thread should be set before TraceEvents are
	// logged. This thread will eventually run the network, so call it now.
	TraceEvent::setNetworkThread();

	try {
		db = Database::createDatabase(ccf, -1, IsInternal::False);
		if (!opt.exec.present()) {
			printf("Using cluster file `%s'.\n", ccf->getFilename().c_str());
		}
	} catch (Error& e) {
		fprintf(stderr, "ERROR: %s (%d)\n", e.what(), e.code());
		printf("Unable to connect to cluster from `%s'\n", ccf->getFilename().c_str());
		return 1;
	}

	// Note: refactoring work, will remove the above code finally
	try {
		db2 = API->createDatabase(opt.clusterFile.c_str());
	} catch (Error& e) {
		fprintf(stderr, "ERROR: %s (%d)\n", e.what(), e.code());
		printf("Unable to connect to cluster from `%s'\n", ccf->getFilename().c_str());
		return 1;
	}

	if (opt.trace) {
		TraceEvent("CLIProgramStart")
		    .setMaxEventLength(12000)
		    .detail("SourceVersion", getSourceVersion())
		    .detail("Version", FDB_VT_VERSION)
		    .detail("PackageName", FDB_VT_PACKAGE_NAME)
		    .detailf("ActualTime", "%lld", DEBUG_DETERMINISM ? 0 : time(nullptr))
		    .detail("ClusterFile", ccf->getFilename().c_str())
		    .detail("ConnectionString", ccf->getConnectionString().toString())
		    .setMaxFieldLength(10000)
		    .detail("CommandLine", opt.commandLine)
		    .trackLatest("ProgramStart");
	}

	if (!opt.exec.present()) {
		if (opt.initialStatusCheck) {
			Future<Void> checkStatusF = checkStatus(Void(), db);
			wait(makeInterruptable(success(checkStatusF)));
		} else {
			printf("\n");
		}

		printf("Welcome to the fdbcli. For help, type `help'.\n");
		validOptions = options->getValidOptions();
	}

	state bool is_error = false;

	state Future<Void> warn;
	loop {
		if (warn.isValid())
			warn.cancel();

		state std::string line;

		if (opt.exec.present()) {
			line = opt.exec.get();
		} else {
			Optional<std::string> rawline = wait(linenoise.read("fdb> "));
			if (!rawline.present()) {
				printf("\n");
				return 0;
			}
			line = rawline.get();

			if (!line.size())
				continue;

			// Don't put dangerous commands in the command history
			if (line.find("writemode") == std::string::npos && line.find("expensive_data_check") == std::string::npos &&
			    line.find("unlock") == std::string::npos)
				linenoise.historyAdd(line);
		}

		warn = checkStatus(timeWarning(5.0, "\nWARNING: Long delay (Ctrl-C to interrupt)\n"), db);

		try {
			state UID randomID = deterministicRandom()->randomUniqueID();
			TraceEvent(SevInfo, "CLICommandLog", randomID).detail("Command", line);

			bool malformed, partial;
			state std::vector<std::vector<StringRef>> parsed = parseLine(line, malformed, partial);
			if (malformed)
				LogCommand(line, randomID, "ERROR: malformed escape sequence");
			if (partial)
				LogCommand(line, randomID, "ERROR: unterminated quote");
			if (malformed || partial) {
				if (parsed.size() > 0) {
					// Denote via a special token that the command was a parse failure.
					auto& last_command = parsed.back();
					last_command.insert(last_command.begin(),
					                    StringRef((const uint8_t*)"parse_error", strlen("parse_error")));
				}
			}

			state bool multi = parsed.size() > 1;
			is_error = false;

			state std::vector<std::vector<StringRef>>::iterator iter;
			for (iter = parsed.begin(); iter != parsed.end(); ++iter) {
				state std::vector<StringRef> tokens = *iter;

				if (is_error) {
					printf("WARNING: the previous command failed, the remaining commands will not be executed.\n");
					break;
				}

				if (!tokens.size())
					continue;

				if (tokencmp(tokens[0], "parse_error")) {
					fprintf(stderr, "ERROR: Command failed to completely parse.\n");
					if (tokens.size() > 1) {
						fprintf(stderr, "ERROR: Not running partial or malformed command:");
						for (auto t = tokens.begin() + 1; t != tokens.end(); ++t)
							printf(" %s", formatStringRef(*t, true).c_str());
						printf("\n");
					}
					is_error = true;
					continue;
				}

				if (multi) {
					printf(">>>");
					for (auto t = tokens.begin(); t != tokens.end(); ++t)
						printf(" %s", formatStringRef(*t, true).c_str());
					printf("\n");
				}

				if (!helpMap.count(tokens[0].toString()) && !hiddenCommands.count(tokens[0].toString())) {
					fprintf(stderr, "ERROR: Unknown command `%s'. Try `help'?\n", formatStringRef(tokens[0]).c_str());
					is_error = true;
					continue;
				}

				if (tokencmp(tokens[0], "exit") || tokencmp(tokens[0], "quit")) {
					return 0;
				}

				if (tokencmp(tokens[0], "help")) {
					if (tokens.size() == 1) {
						printHelpOverview();
					} else if (tokens.size() == 2) {
						if (tokencmp(tokens[1], "escaping"))
							printf("\n"
							       "When parsing commands, fdbcli considers a space to delimit individual tokens.\n"
							       "To include a space in a single token, you may either enclose the token in\n"
							       "quotation marks (\"hello world\"), prefix the space with a backslash\n"
							       "(hello\\ world), or encode the space as a hex byte (hello\\x20world).\n"
							       "\n"
							       "To include a literal quotation mark in a token, precede it with a backslash\n"
							       "(\\\"hello\\ world\\\").\n"
							       "\n"
							       "To express a binary value, encode each byte as a two-digit hex byte, preceded\n"
							       "by \\x (e.g. \\x20 for a space character, or \\x0a\\x00\\x00\\x00 for a\n"
							       "32-bit, little-endian representation of the integer 10).\n"
							       "\n"
							       "All keys and values are displayed by the fdbcli with non-printable characters\n"
							       "and spaces encoded as two-digit hex bytes.\n\n");
						else if (tokencmp(tokens[1], "options")) {
							printf("\n"
							       "The following options are available to be set using the `option' command:\n"
							       "\n");
							options->printHelpString();
						} else if (tokencmp(tokens[1], "help"))
							printHelpOverview();
						else
							printHelp(tokens[1]);
					} else
						printf("Usage: help [topic]\n");
					continue;
				}

				if (tokencmp(tokens[0], "waitconnected")) {
					wait(makeInterruptable(db->onConnected()));
					continue;
				}

				if (tokencmp(tokens[0], "waitopen")) {
					wait(success(getTransaction(db, tr, options, intrans)->getReadVersion()));
					continue;
				}

				if (tokencmp(tokens[0], "sleep")) {
					if (tokens.size() != 2) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						double v;
						int n = 0;
						if (sscanf(tokens[1].toString().c_str(), "%lf%n", &v, &n) != 1 || n != tokens[1].size()) {
							printUsage(tokens[0]);
							is_error = true;
						} else {
							wait(delay(v));
						}
					}
					continue;
				}

				if (tokencmp(tokens[0], "status")) {
					// Warn at 7 seconds since status will spend as long as 5 seconds trying to read/write from the
					// database
					warn = timeWarning(7.0, "\nWARNING: Long delay (Ctrl-C to interrupt)\n");

					state StatusClient::StatusLevel level;
					if (tokens.size() == 1)
						level = StatusClient::NORMAL;
					else if (tokens.size() == 2 && tokencmp(tokens[1], "details"))
						level = StatusClient::DETAILED;
					else if (tokens.size() == 2 && tokencmp(tokens[1], "minimal"))
						level = StatusClient::MINIMAL;
					else if (tokens.size() == 2 && tokencmp(tokens[1], "json"))
						level = StatusClient::JSON;
					else {
						printUsage(tokens[0]);
						is_error = true;
						continue;
					}

					StatusObject s = wait(makeInterruptable(StatusClient::statusFetcher(db)));

					if (!opt.exec.present())
						printf("\n");
					printStatus(s, level);
					if (!opt.exec.present())
						printf("\n");
					continue;
				}

				if (tokencmp(tokens[0], "triggerddteaminfolog")) {
					wait(triggerDDTeamInfoLog(db));
					continue;
				}

				if (tokencmp(tokens[0], "tssq")) {
					if (tokens.size() == 2) {
						if (tokens[1] != LiteralStringRef("list")) {
							printUsage(tokens[0]);
							is_error = true;
						} else {
							wait(tssQuarantineList(db));
						}
					}
					if (tokens.size() == 3) {
						if ((tokens[1] != LiteralStringRef("start") && tokens[1] != LiteralStringRef("stop")) ||
						    (tokens[2].size() != 32) || !std::all_of(tokens[2].begin(), tokens[2].end(), &isxdigit)) {
							printUsage(tokens[0]);
							is_error = true;
						} else {
							bool enable = tokens[1] == LiteralStringRef("start");
							UID tssId = UID::fromString(tokens[2].toString());
							bool err = wait(tssQuarantine(db, enable, tssId));
							if (err)
								is_error = true;
						}
					}
					continue;
				}

				if (tokencmp(tokens[0], "configure")) {
					bool err = wait(configure(db, tokens, db->getConnectionFile(), &linenoise, warn));
					if (err)
						is_error = true;
					continue;
				}

				if (tokencmp(tokens[0], "fileconfigure")) {
					if (tokens.size() == 2 || (tokens.size() == 3 && (tokens[1] == LiteralStringRef("new") ||
					                                                  tokens[1] == LiteralStringRef("FORCE")))) {
						bool err = wait(fileConfigure(db,
						                              tokens.back().toString(),
						                              tokens[1] == LiteralStringRef("new"),
						                              tokens[1] == LiteralStringRef("FORCE")));
						if (err)
							is_error = true;
					} else {
						printUsage(tokens[0]);
						is_error = true;
					}
					continue;
				}

				if (tokencmp(tokens[0], "coordinators")) {
					auto cs = ClusterConnectionFile(db->getConnectionFile()->getFilename()).getConnectionString();
					if (tokens.size() < 2) {
						printf("Cluster description: %s\n", cs.clusterKeyName().toString().c_str());
						printf("Cluster coordinators (%zu): %s\n",
						       cs.coordinators().size(),
						       describe(cs.coordinators()).c_str());
						printf("Type `help coordinators' to learn how to change this information.\n");
					} else {
						bool err = wait(coordinators(db, tokens, cs.coordinators()[0].isTLS()));
						if (err)
							is_error = true;
					}
					continue;
				}

				if (tokencmp(tokens[0], "exclude")) {
					bool err = wait(exclude(db, tokens, db->getConnectionFile(), warn));
					if (err)
						is_error = true;
					continue;
				}

				if (tokencmp(tokens[0], "include")) {
					if (tokens.size() < 2) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						bool err = wait(include(db, tokens));
						if (err)
							is_error = true;
					}
					continue;
				}

				if (tokencmp(tokens[0], "snapshot")) {
					bool _result = wait(snapshotCommandActor(db2, tokens));
					if (!_result)
						is_error = true;
					continue;
				}

				if (tokencmp(tokens[0], "lock")) {
					if (tokens.size() != 1) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						state UID lockUID = deterministicRandom()->randomUniqueID();
						printf("Locking database with lockUID: %s\n", lockUID.toString().c_str());
						wait(makeInterruptable(lockDatabase(db, lockUID)));
						printf("Database locked.\n");
					}
					continue;
				}

				if (tokencmp(tokens[0], "unlock")) {
					if ((tokens.size() != 2) || (tokens[1].size() != 32) ||
					    !std::all_of(tokens[1].begin(), tokens[1].end(), &isxdigit)) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						state std::string passPhrase = deterministicRandom()->randomAlphaNumeric(10);
						warn.cancel(); // don't warn while waiting on user input
						printf("Unlocking the database is a potentially dangerous operation.\n");
						printf("%s\n", passPhrase.c_str());
						fflush(stdout);
						Optional<std::string> input =
						    wait(linenoise.read(format("Repeat the above passphrase if you would like to proceed:")));
						warn = checkStatus(timeWarning(5.0, "\nWARNING: Long delay (Ctrl-C to interrupt)\n"), db);
						if (input.present() && input.get() == passPhrase) {
							UID unlockUID = UID::fromString(tokens[1].toString());
							try {
								wait(makeInterruptable(unlockDatabase(db, unlockUID)));
								printf("Database unlocked.\n");
							} catch (Error& e) {
								if (e.code() == error_code_database_locked) {
									printf(
									    "Unable to unlock database. Make sure to unlock with the correct lock UID.\n");
								}
								throw e;
							}
						} else {
							fprintf(stderr, "ERROR: Incorrect passphrase entered.\n");
							is_error = true;
						}
					}
					continue;
				}

				if (tokencmp(tokens[0], "setclass")) {
					bool _result = wait(makeInterruptable(setClassCommandActor(db2, tokens)));
					if (!_result)
						is_error = true;
					continue;
				}

				if (tokencmp(tokens[0], "begin")) {
					if (tokens.size() != 1) {
						printUsage(tokens[0]);
						is_error = true;
					} else if (intrans) {
						fprintf(stderr, "ERROR: Already in transaction\n");
						is_error = true;
					} else {
						activeOptions = FdbOptions(globalOptions);
						options = &activeOptions;
						getTransaction(db, tr, options, false);
						intrans = true;
						printf("Transaction started\n");
					}
					continue;
				}

				if (tokencmp(tokens[0], "commit")) {
					if (tokens.size() != 1) {
						printUsage(tokens[0]);
						is_error = true;
					} else if (!intrans) {
						fprintf(stderr, "ERROR: No active transaction\n");
						is_error = true;
					} else {
						wait(commitTransaction(tr));
						intrans = false;
						options = &globalOptions;
					}

					continue;
				}

				if (tokencmp(tokens[0], "reset")) {
					if (tokens.size() != 1) {
						printUsage(tokens[0]);
						is_error = true;
					} else if (!intrans) {
						fprintf(stderr, "ERROR: No active transaction\n");
						is_error = true;
					} else {
						tr->reset();
						activeOptions = FdbOptions(globalOptions);
						options = &activeOptions;
						options->apply(tr);
						printf("Transaction reset\n");
					}
					continue;
				}

				if (tokencmp(tokens[0], "rollback")) {
					if (tokens.size() != 1) {
						printUsage(tokens[0]);
						is_error = true;
					} else if (!intrans) {
						fprintf(stderr, "ERROR: No active transaction\n");
						is_error = true;
					} else {
						intrans = false;
						options = &globalOptions;
						printf("Transaction rolled back\n");
					}
					continue;
				}

				if (tokencmp(tokens[0], "get")) {
					if (tokens.size() != 2) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						Optional<Standalone<StringRef>> v =
						    wait(makeInterruptable(getTransaction(db, tr, options, intrans)->get(tokens[1])));

						if (v.present())
							printf("`%s' is `%s'\n", printable(tokens[1]).c_str(), printable(v.get()).c_str());
						else
							printf("`%s': not found\n", printable(tokens[1]).c_str());
					}
					continue;
				}

				if (tokencmp(tokens[0], "getversion")) {
					if (tokens.size() != 1) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						Version v = wait(makeInterruptable(getTransaction(db, tr, options, intrans)->getReadVersion()));
						printf("%ld\n", v);
					}
					continue;
				}

				if (tokencmp(tokens[0], "advanceversion")) {
					bool _result = wait(makeInterruptable(advanceVersionCommandActor(db2, tokens)));
					if (!_result)
						is_error = true;
					continue;
				}

				if (tokencmp(tokens[0], "kill")) {
					getTransaction(db, tr, options, intrans);
					if (tokens.size() == 1) {
						RangeResult kvs = wait(
						    makeInterruptable(tr->getRange(KeyRangeRef(LiteralStringRef("\xff\xff/worker_interfaces/"),
						                                               LiteralStringRef("\xff\xff/worker_interfaces0")),
						                                   CLIENT_KNOBS->TOO_MANY)));
						ASSERT(!kvs.more);
						auto connectLock = makeReference<FlowLock>(CLIENT_KNOBS->CLI_CONNECT_PARALLELISM);
						std::vector<Future<Void>> addInterfs;
						for (auto it : kvs) {
							addInterfs.push_back(addInterface(&address_interface, connectLock, it));
						}
						wait(waitForAll(addInterfs));
					}
					if (tokens.size() == 1 || tokencmp(tokens[1], "list")) {
						if (address_interface.size() == 0) {
							printf("\nNo addresses can be killed.\n");
						} else if (address_interface.size() == 1) {
							printf("\nThe following address can be killed:\n");
						} else {
							printf("\nThe following %zu addresses can be killed:\n", address_interface.size());
						}
						for (auto it : address_interface) {
							printf("%s\n", printable(it.first).c_str());
						}
						printf("\n");
					} else if (tokencmp(tokens[1], "all")) {
						for (auto it : address_interface) {
							BinaryReader::fromStringRef<ClientWorkerInterface>(it.second.first, IncludeVersion())
							    .reboot.send(RebootRequest());
						}
						if (address_interface.size() == 0) {
							fprintf(stderr,
							        "ERROR: no processes to kill. You must run the `kill’ command before "
							        "running `kill all’.\n");
						} else {
							printf("Attempted to kill %zu processes\n", address_interface.size());
						}
					} else {
						for (int i = 1; i < tokens.size(); i++) {
							if (!address_interface.count(tokens[i])) {
								fprintf(stderr, "ERROR: process `%s' not recognized.\n", printable(tokens[i]).c_str());
								is_error = true;
								break;
							}
						}

						if (!is_error) {
							for (int i = 1; i < tokens.size(); i++) {
								BinaryReader::fromStringRef<ClientWorkerInterface>(address_interface[tokens[i]].first,
								                                                   IncludeVersion())
								    .reboot.send(RebootRequest());
							}
							printf("Attempted to kill %zu processes\n", tokens.size() - 1);
						}
					}
					continue;
				}

				if (tokencmp(tokens[0], "suspend")) {
					getTransaction(db, tr, options, intrans);
					if (tokens.size() == 1) {
						RangeResult kvs = wait(
						    makeInterruptable(tr->getRange(KeyRangeRef(LiteralStringRef("\xff\xff/worker_interfaces/"),
						                                               LiteralStringRef("\xff\xff/worker_interfaces0")),
						                                   CLIENT_KNOBS->TOO_MANY)));
						ASSERT(!kvs.more);
						auto connectLock = makeReference<FlowLock>(CLIENT_KNOBS->CLI_CONNECT_PARALLELISM);
						std::vector<Future<Void>> addInterfs;
						for (auto it : kvs) {
							addInterfs.push_back(addInterface(&address_interface, connectLock, it));
						}
						wait(waitForAll(addInterfs));
						if (address_interface.size() == 0) {
							printf("\nNo addresses can be suspended.\n");
						} else if (address_interface.size() == 1) {
							printf("\nThe following address can be suspended:\n");
						} else {
							printf("\nThe following %zu addresses can be suspended:\n", address_interface.size());
						}
						for (auto it : address_interface) {
							printf("%s\n", printable(it.first).c_str());
						}
						printf("\n");
					} else if (tokens.size() == 2) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						for (int i = 2; i < tokens.size(); i++) {
							if (!address_interface.count(tokens[i])) {
								fprintf(stderr, "ERROR: process `%s' not recognized.\n", printable(tokens[i]).c_str());
								is_error = true;
								break;
							}
						}

						if (!is_error) {
							double seconds;
							int n = 0;
							auto secondsStr = tokens[1].toString();
							if (sscanf(secondsStr.c_str(), "%lf%n", &seconds, &n) != 1 || n != secondsStr.size()) {
								printUsage(tokens[0]);
								is_error = true;
							} else {
								int64_t timeout_ms = seconds * 1000;
								tr->setOption(FDBTransactionOptions::TIMEOUT,
								              StringRef((uint8_t*)&timeout_ms, sizeof(int64_t)));
								for (int i = 2; i < tokens.size(); i++) {
									BinaryReader::fromStringRef<ClientWorkerInterface>(
									    address_interface[tokens[i]].first, IncludeVersion())
									    .reboot.send(RebootRequest(false, false, seconds));
								}
								printf("Attempted to suspend %zu processes\n", tokens.size() - 2);
							}
						}
					}
					continue;
				}

				if (tokencmp(tokens[0], "force_recovery_with_data_loss")) {
					bool _result = wait(makeInterruptable(forceRecoveryWithDataLossCommandActor(db2, tokens)));
					if (!_result)
						is_error = true;
					continue;
				}

				if (tokencmp(tokens[0], "maintenance")) {
					bool _result = wait(makeInterruptable(maintenanceCommandActor(db2, tokens)));
					if (!_result)
						is_error = true;
					continue;
				}

				if (tokencmp(tokens[0], "consistencycheck")) {
					getTransaction(db, tr, tr2, options, intrans);
					bool _result = wait(makeInterruptable(consistencyCheckCommandActor(tr2, tokens)));
					if (!_result)
						is_error = true;
					continue;
				}

				if (tokencmp(tokens[0], "profile")) {
					if (tokens.size() == 1) {
						fprintf(stderr, "ERROR: Usage: profile <client|list|flow|heap>\n");
						is_error = true;
						continue;
					}
					if (tokencmp(tokens[1], "client")) {
						getTransaction(db, tr, options, intrans);
						tr->setOption(FDBTransactionOptions::ACCESS_SYSTEM_KEYS);
						if (tokens.size() == 2) {
							fprintf(stderr, "ERROR: Usage: profile client <get|set>\n");
							is_error = true;
							continue;
						}
						wait(makeInterruptable(GlobalConfig::globalConfig().onInitialized()));
						if (tokencmp(tokens[2], "get")) {
							if (tokens.size() != 3) {
								fprintf(stderr, "ERROR: Addtional arguments to `get` are not supported.\n");
								is_error = true;
								continue;
							}
							const double sampleRateDbl = GlobalConfig::globalConfig().get<double>(
							    fdbClientInfoTxnSampleRate, std::numeric_limits<double>::infinity());
							const int64_t sizeLimit =
							    GlobalConfig::globalConfig().get<int64_t>(fdbClientInfoTxnSizeLimit, -1);
							std::string sampleRateStr = "default", sizeLimitStr = "default";
							if (!std::isinf(sampleRateDbl)) {
								sampleRateStr = boost::lexical_cast<std::string>(sampleRateDbl);
							}
							if (sizeLimit != -1) {
								sizeLimitStr = boost::lexical_cast<std::string>(sizeLimit);
							}
							printf("Client profiling rate is set to %s and size limit is set to %s.\n",
							       sampleRateStr.c_str(),
							       sizeLimitStr.c_str());
							continue;
						}
						if (tokencmp(tokens[2], "set")) {
							if (tokens.size() != 5) {
								fprintf(stderr, "ERROR: Usage: profile client set <RATE|default> <SIZE|default>\n");
								is_error = true;
								continue;
							}
							double sampleRate;
							if (tokencmp(tokens[3], "default")) {
								sampleRate = std::numeric_limits<double>::infinity();
							} else {
								char* end;
								sampleRate = std::strtod((const char*)tokens[3].begin(), &end);
								if (!std::isspace(*end)) {
									fprintf(stderr, "ERROR: %s failed to parse.\n", printable(tokens[3]).c_str());
									is_error = true;
									continue;
								}
							}
							int64_t sizeLimit;
							if (tokencmp(tokens[4], "default")) {
								sizeLimit = -1;
							} else {
								Optional<uint64_t> parsed = parse_with_suffix(tokens[4].toString());
								if (parsed.present()) {
									sizeLimit = parsed.get();
								} else {
									fprintf(stderr, "ERROR: `%s` failed to parse.\n", printable(tokens[4]).c_str());
									is_error = true;
									continue;
								}
							}

							Tuple rate = Tuple().appendDouble(sampleRate);
							Tuple size = Tuple().append(sizeLimit);
							tr->setOption(FDBTransactionOptions::SPECIAL_KEY_SPACE_ENABLE_WRITES);
							tr->set(GlobalConfig::prefixedKey(fdbClientInfoTxnSampleRate), rate.pack());
							tr->set(GlobalConfig::prefixedKey(fdbClientInfoTxnSizeLimit), size.pack());
							if (!intrans) {
								wait(commitTransaction(tr));
							}
							continue;
						}
						fprintf(stderr, "ERROR: Unknown action: %s\n", printable(tokens[2]).c_str());
						is_error = true;
						continue;
					}
					if (tokencmp(tokens[1], "list")) {
						if (tokens.size() != 2) {
							fprintf(stderr, "ERROR: Usage: profile list\n");
							is_error = true;
							continue;
						}
						getTransaction(db, tr, options, intrans);
						RangeResult kvs = wait(
						    makeInterruptable(tr->getRange(KeyRangeRef(LiteralStringRef("\xff\xff/worker_interfaces/"),
						                                               LiteralStringRef("\xff\xff/worker_interfaces0")),
						                                   CLIENT_KNOBS->TOO_MANY)));
						ASSERT(!kvs.more);
						for (const auto& pair : kvs) {
							auto ip_port = (pair.key.endsWith(LiteralStringRef(":tls"))
							                    ? pair.key.removeSuffix(LiteralStringRef(":tls"))
							                    : pair.key)
							                   .removePrefix(LiteralStringRef("\xff\xff/worker_interfaces/"));
							printf("%s\n", printable(ip_port).c_str());
						}
						continue;
					}
					if (tokencmp(tokens[1], "flow")) {
						if (tokens.size() == 2) {
							fprintf(stderr, "ERROR: Usage: profile flow <run>\n");
							is_error = true;
							continue;
						}
						if (tokencmp(tokens[2], "run")) {
							if (tokens.size() < 6) {
								fprintf(
								    stderr,
								    "ERROR: Usage: profile flow run <DURATION_IN_SECONDS> <FILENAME> <PROCESS...>\n");
								is_error = true;
								continue;
							}
							getTransaction(db, tr, options, intrans);
							RangeResult kvs = wait(makeInterruptable(
							    tr->getRange(KeyRangeRef(LiteralStringRef("\xff\xff/worker_interfaces/"),
							                             LiteralStringRef("\xff\xff/worker_interfaces0")),
							                 CLIENT_KNOBS->TOO_MANY)));
							ASSERT(!kvs.more);
							char* duration_end;
							int duration = std::strtol((const char*)tokens[3].begin(), &duration_end, 10);
							if (!std::isspace(*duration_end)) {
								fprintf(
								    stderr, "ERROR: Failed to parse %s as an integer.", printable(tokens[3]).c_str());
								is_error = true;
								continue;
							}
							std::map<Key, ClientWorkerInterface> interfaces;
							state std::vector<Key> all_profiler_addresses;
							state std::vector<Future<ErrorOr<Void>>> all_profiler_responses;
							for (const auto& pair : kvs) {
								auto ip_port = (pair.key.endsWith(LiteralStringRef(":tls"))
								                    ? pair.key.removeSuffix(LiteralStringRef(":tls"))
								                    : pair.key)
								                   .removePrefix(LiteralStringRef("\xff\xff/worker_interfaces/"));
								interfaces.emplace(
								    ip_port,
								    BinaryReader::fromStringRef<ClientWorkerInterface>(pair.value, IncludeVersion()));
							}
							if (tokens.size() == 6 && tokencmp(tokens[5], "all")) {
								for (const auto& pair : interfaces) {
									ProfilerRequest profileRequest(
									    ProfilerRequest::Type::FLOW, ProfilerRequest::Action::RUN, duration);
									profileRequest.outputFile = tokens[4];
									all_profiler_addresses.push_back(pair.first);
									all_profiler_responses.push_back(pair.second.profiler.tryGetReply(profileRequest));
								}
							} else {
								for (int tokenidx = 5; tokenidx < tokens.size(); tokenidx++) {
									auto element = interfaces.find(tokens[tokenidx]);
									if (element == interfaces.end()) {
										fprintf(stderr,
										        "ERROR: process '%s' not recognized.\n",
										        printable(tokens[tokenidx]).c_str());
										is_error = true;
									}
								}
								if (!is_error) {
									for (int tokenidx = 5; tokenidx < tokens.size(); tokenidx++) {
										ProfilerRequest profileRequest(
										    ProfilerRequest::Type::FLOW, ProfilerRequest::Action::RUN, duration);
										profileRequest.outputFile = tokens[4];
										all_profiler_addresses.push_back(tokens[tokenidx]);
										all_profiler_responses.push_back(
										    interfaces[tokens[tokenidx]].profiler.tryGetReply(profileRequest));
									}
								}
							}
							if (!is_error) {
								wait(waitForAll(all_profiler_responses));
								for (int i = 0; i < all_profiler_responses.size(); i++) {
									const ErrorOr<Void>& err = all_profiler_responses[i].get();
									if (err.isError()) {
										fprintf(stderr,
										        "ERROR: %s: %s: %s\n",
										        printable(all_profiler_addresses[i]).c_str(),
										        err.getError().name(),
										        err.getError().what());
									}
								}
							}
							all_profiler_addresses.clear();
							all_profiler_responses.clear();
							continue;
						}
					}
					if (tokencmp(tokens[1], "heap")) {
						if (tokens.size() != 3) {
							fprintf(stderr, "ERROR: Usage: profile heap <PROCESS>\n");
							is_error = true;
							continue;
						}
						getTransaction(db, tr, options, intrans);
						RangeResult kvs = wait(
						    makeInterruptable(tr->getRange(KeyRangeRef(LiteralStringRef("\xff\xff/worker_interfaces/"),
						                                               LiteralStringRef("\xff\xff/worker_interfaces0")),
						                                   CLIENT_KNOBS->TOO_MANY)));
						ASSERT(!kvs.more);
						std::map<Key, ClientWorkerInterface> interfaces;
						for (const auto& pair : kvs) {
							auto ip_port = (pair.key.endsWith(LiteralStringRef(":tls"))
							                    ? pair.key.removeSuffix(LiteralStringRef(":tls"))
							                    : pair.key)
							                   .removePrefix(LiteralStringRef("\xff\xff/worker_interfaces/"));
							interfaces.emplace(
							    ip_port,
							    BinaryReader::fromStringRef<ClientWorkerInterface>(pair.value, IncludeVersion()));
						}
						state Key ip_port = tokens[2];
						if (interfaces.find(ip_port) == interfaces.end()) {
							fprintf(stderr, "ERROR: host %s not found\n", printable(ip_port).c_str());
							is_error = true;
							continue;
						}
						ProfilerRequest profileRequest(
						    ProfilerRequest::Type::GPROF_HEAP, ProfilerRequest::Action::RUN, 0);
						profileRequest.outputFile = LiteralStringRef("heapz");
						ErrorOr<Void> response = wait(interfaces[ip_port].profiler.tryGetReply(profileRequest));
						if (response.isError()) {
							fprintf(stderr,
							        "ERROR: %s: %s: %s\n",
							        printable(ip_port).c_str(),
							        response.getError().name(),
							        response.getError().what());
						}
						continue;
					}
					fprintf(stderr, "ERROR: Unknown type: %s\n", printable(tokens[1]).c_str());
					is_error = true;
					continue;
				}

				if (tokencmp(tokens[0], "expensive_data_check")) {
					getTransaction(db, tr, options, intrans);
					if (tokens.size() == 1) {
						RangeResult kvs = wait(
						    makeInterruptable(tr->getRange(KeyRangeRef(LiteralStringRef("\xff\xff/worker_interfaces/"),
						                                               LiteralStringRef("\xff\xff/worker_interfaces0")),
						                                   CLIENT_KNOBS->TOO_MANY)));
						ASSERT(!kvs.more);
						auto connectLock = makeReference<FlowLock>(CLIENT_KNOBS->CLI_CONNECT_PARALLELISM);
						std::vector<Future<Void>> addInterfs;
						for (auto it : kvs) {
							addInterfs.push_back(addInterface(&address_interface, connectLock, it));
						}
						wait(waitForAll(addInterfs));
					}
					if (tokens.size() == 1 || tokencmp(tokens[1], "list")) {
						if (address_interface.size() == 0) {
							printf("\nNo addresses can be checked.\n");
						} else if (address_interface.size() == 1) {
							printf("\nThe following address can be checked:\n");
						} else {
							printf("\nThe following %zu addresses can be checked:\n", address_interface.size());
						}
						for (auto it : address_interface) {
							printf("%s\n", printable(it.first).c_str());
						}
						printf("\n");
					} else if (tokencmp(tokens[1], "all")) {
						for (auto it : address_interface) {
							BinaryReader::fromStringRef<ClientWorkerInterface>(it.second.first, IncludeVersion())
							    .reboot.send(RebootRequest(false, true));
						}
						if (address_interface.size() == 0) {
							fprintf(stderr,
							        "ERROR: no processes to check. You must run the `expensive_data_check’ "
							        "command before running `expensive_data_check all’.\n");
						} else {
							printf("Attempted to kill and check %zu processes\n", address_interface.size());
						}
					} else {
						for (int i = 1; i < tokens.size(); i++) {
							if (!address_interface.count(tokens[i])) {
								fprintf(stderr, "ERROR: process `%s' not recognized.\n", printable(tokens[i]).c_str());
								is_error = true;
								break;
							}
						}

						if (!is_error) {
							for (int i = 1; i < tokens.size(); i++) {
								BinaryReader::fromStringRef<ClientWorkerInterface>(address_interface[tokens[i]].first,
								                                                   IncludeVersion())
								    .reboot.send(RebootRequest(false, true));
							}
							printf("Attempted to kill and check %zu processes\n", tokens.size() - 1);
						}
					}
					continue;
				}

				if (tokencmp(tokens[0], "getrange") ||
				    tokencmp(tokens[0], "getrangekeys")) { // FIXME: support byte limits, and reverse range reads
					if (tokens.size() < 2 || tokens.size() > 4) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						state int limit;
						bool valid = true;

						if (tokens.size() == 4) {
							// INT_MAX is 10 digits; rather than
							// worrying about overflow we'll just cap
							// limit at the (already absurd)
							// nearly-a-billion
							if (tokens[3].size() > 9) {
								fprintf(stderr, "ERROR: bad limit\n");
								is_error = true;
								continue;
							}
							limit = 0;
							int place = 1;
							for (int i = tokens[3].size(); i > 0; i--) {
								int val = int(tokens[3][i - 1]) - int('0');
								if (val < 0 || val > 9) {
									valid = false;
									break;
								}
								limit += val * place;
								place *= 10;
							}
							if (!valid) {
								fprintf(stderr, "ERROR: bad limit\n");
								is_error = true;
								continue;
							}
						} else {
							limit = 25;
						}

						Standalone<StringRef> endKey;
						if (tokens.size() >= 3) {
							endKey = tokens[2];
						} else if (tokens[1].size() == 0) {
							endKey = normalKeys.end;
						} else if (tokens[1] == systemKeys.begin) {
							endKey = systemKeys.end;
						} else if (tokens[1] >= allKeys.end) {
							throw key_outside_legal_range();
						} else {
							endKey = strinc(tokens[1]);
						}

						RangeResult kvs = wait(makeInterruptable(
						    getTransaction(db, tr, options, intrans)->getRange(KeyRangeRef(tokens[1], endKey), limit)));

						printf("\nRange limited to %d keys\n", limit);
						for (auto iter = kvs.begin(); iter < kvs.end(); iter++) {
							if (tokencmp(tokens[0], "getrangekeys"))
								printf("`%s'\n", printable((*iter).key).c_str());
							else
								printf(
								    "`%s' is `%s'\n", printable((*iter).key).c_str(), printable((*iter).value).c_str());
						}
						printf("\n");
					}
					continue;
				}

				if (tokencmp(tokens[0], "writemode")) {
					if (tokens.size() != 2) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						if (tokencmp(tokens[1], "on")) {
							writeMode = true;
						} else if (tokencmp(tokens[1], "off")) {
							writeMode = false;
						} else {
							printUsage(tokens[0]);
							is_error = true;
						}
					}
					continue;
				}

				if (tokencmp(tokens[0], "set")) {
					if (!writeMode) {
						fprintf(stderr, "ERROR: writemode must be enabled to set or clear keys in the database.\n");
						is_error = true;
						continue;
					}

					if (tokens.size() != 3) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						getTransaction(db, tr, options, intrans);
						tr->set(tokens[1], tokens[2]);

						if (!intrans) {
							wait(commitTransaction(tr));
						}
					}
					continue;
				}

				if (tokencmp(tokens[0], "clear")) {
					if (!writeMode) {
						fprintf(stderr, "ERROR: writemode must be enabled to set or clear keys in the database.\n");
						is_error = true;
						continue;
					}

					if (tokens.size() != 2) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						getTransaction(db, tr, options, intrans);
						tr->clear(tokens[1]);

						if (!intrans) {
							wait(commitTransaction(tr));
						}
					}
					continue;
				}

				if (tokencmp(tokens[0], "clearrange")) {
					if (!writeMode) {
						fprintf(stderr, "ERROR: writemode must be enabled to set or clear keys in the database.\n");
						is_error = true;
						continue;
					}

					if (tokens.size() != 3) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						getTransaction(db, tr, options, intrans);
						tr->clear(KeyRangeRef(tokens[1], tokens[2]));

						if (!intrans) {
							wait(commitTransaction(tr));
						}
					}
					continue;
				}

				if (tokencmp(tokens[0], "datadistribution")) {
					if (tokens.size() != 2 && tokens.size() != 3) {
						printf("Usage: datadistribution <on|off|disable <ssfailure|rebalance>|enable "
						       "<ssfailure|rebalance>>\n");
						is_error = true;
					} else {
						if (tokencmp(tokens[1], "on")) {
							wait(success(setDDMode(db, 1)));
							printf("Data distribution is turned on.\n");
						} else if (tokencmp(tokens[1], "off")) {
							wait(success(setDDMode(db, 0)));
							printf("Data distribution is turned off.\n");
						} else if (tokencmp(tokens[1], "disable")) {
							if (tokencmp(tokens[2], "ssfailure")) {
								wait(success(makeInterruptable(setHealthyZone(db, ignoreSSFailuresZoneString, 0))));
								printf("Data distribution is disabled for storage server failures.\n");
							} else if (tokencmp(tokens[2], "rebalance")) {
								wait(makeInterruptable(setDDIgnoreRebalanceSwitch(db, true)));
								printf("Data distribution is disabled for rebalance.\n");
							} else {
								printf("Usage: datadistribution <on|off|disable <ssfailure|rebalance>|enable "
								       "<ssfailure|rebalance>>\n");
								is_error = true;
							}
						} else if (tokencmp(tokens[1], "enable")) {
							if (tokencmp(tokens[2], "ssfailure")) {
								wait(success(makeInterruptable(clearHealthyZone(db, false, true))));
								printf("Data distribution is enabled for storage server failures.\n");
							} else if (tokencmp(tokens[2], "rebalance")) {
								wait(makeInterruptable(setDDIgnoreRebalanceSwitch(db, false)));
								printf("Data distribution is enabled for rebalance.\n");
							} else {
								printf("Usage: datadistribution <on|off|disable <ssfailure|rebalance>|enable "
								       "<ssfailure|rebalance>>\n");
								is_error = true;
							}
						} else {
							printf("Usage: datadistribution <on|off|disable <ssfailure|rebalance>|enable "
							       "<ssfailure|rebalance>>\n");
							is_error = true;
						}
					}
					continue;
				}

				if (tokencmp(tokens[0], "option")) {
					if (tokens.size() == 2 || tokens.size() > 4) {
						printUsage(tokens[0]);
						is_error = true;
					} else {
						if (tokens.size() == 1) {
							if (options->hasAnyOptionsEnabled()) {
								printf("\nCurrently enabled options:\n\n");
								options->print();
								printf("\n");
							} else
								fprintf(stderr, "There are no options enabled\n");

							continue;
						}
						bool isOn;
						if (tokencmp(tokens[1], "on")) {
							isOn = true;
						} else if (tokencmp(tokens[1], "off")) {
							if (intrans) {
								fprintf(
								    stderr,
								    "ERROR: Cannot turn option off when using a transaction created with `begin'\n");
								is_error = true;
								continue;
							}
							if (tokens.size() > 3) {
								fprintf(stderr, "ERROR: Cannot specify option argument when turning option off\n");
								is_error = true;
								continue;
							}

							isOn = false;
						} else {
							fprintf(stderr,
							        "ERROR: Invalid option state `%s': option must be turned `on' or `off'\n",
							        formatStringRef(tokens[1]).c_str());
							is_error = true;
							continue;
						}

						Optional<StringRef> arg = (tokens.size() > 3) ? tokens[3] : Optional<StringRef>();

						try {
							options->setOption(tr, tokens[2], isOn, arg, intrans);
							printf("Option %s for %s\n",
							       isOn ? "enabled" : "disabled",
							       intrans ? "current transaction" : "all transactions");
						} catch (Error& e) {
							// options->setOption() prints error message
							TraceEvent(SevWarn, "CLISetOptionError").error(e).detail("Option", tokens[2]);
							is_error = true;
						}
					}

					continue;
				}

				if (tokencmp(tokens[0], "throttle")) {
					bool _result = wait(throttleCommandActor(db2, tokens));
					if (!_result)
						is_error = true;
					continue;
				}

				if (tokencmp(tokens[0], "cache_range")) {
					if (tokens.size() != 4) {
						printUsage(tokens[0]);
						is_error = true;
						continue;
					}
					KeyRangeRef cacheRange(tokens[2], tokens[3]);
					if (tokencmp(tokens[1], "set")) {
						wait(makeInterruptable(addCachedRange(db, cacheRange)));
					} else if (tokencmp(tokens[1], "clear")) {
						wait(makeInterruptable(removeCachedRange(db, cacheRange)));
					} else {
						printUsage(tokens[0]);
						is_error = true;
					}
					continue;
				}

				fprintf(stderr, "ERROR: Unknown command `%s'. Try `help'?\n", formatStringRef(tokens[0]).c_str());
				is_error = true;
			}

			TraceEvent(SevInfo, "CLICommandLog", randomID).detail("Command", line).detail("IsError", is_error);

		} catch (Error& e) {
			if (e.code() != error_code_actor_cancelled)
				fprintf(stderr, "ERROR: %s (%d)\n", e.what(), e.code());
			is_error = true;
			if (intrans) {
				printf("Rolling back current transaction\n");
				intrans = false;
				options = &globalOptions;
				options->apply(tr);
			}
		}

		if (opt.exec.present()) {
			return is_error ? 1 : 0;
		}
	}
}

ACTOR Future<int> runCli(CLIOptions opt) {
	state LineNoise linenoise(
	    [](std::string const& line, std::vector<std::string>& completions) { fdbcliCompCmd(line, completions); },
	    [enabled = opt.cliHints](std::string const& line) -> LineNoise::Hint {
		    if (!enabled) {
			    return LineNoise::Hint();
		    }

		    bool error = false;
		    bool partial = false;
		    std::string linecopy = line;
		    std::vector<std::vector<StringRef>> parsed = parseLine(linecopy, error, partial);
		    if (parsed.size() == 0 || parsed.back().size() == 0)
			    return LineNoise::Hint();
		    StringRef command = parsed.back().front();
		    int finishedParameters = parsed.back().size() + error;

		    // As a user is typing an escaped character, e.g. \", after the \ and before the " is typed
		    // the string will be a parse error.  Ignore this parse error to avoid flipping the hint to
		    // {malformed escape sequence} and back to the original hint for the span of one character
		    // being entered.
		    if (error && line.back() != '\\')
			    return LineNoise::Hint(std::string(" {malformed escape sequence}"), 90, false);

		    bool inArgument = *(line.end() - 1) != ' ';
		    std::string hintLine = inArgument ? " " : "";
		    if (tokencmp(command, "throttle")) {
			    std::vector<const char*> hintItems = throttleHintGenerator(parsed.back(), inArgument);
			    if (hintItems.empty()) {
				    return LineNoise::Hint();
			    }
			    for (auto item : hintItems) {
				    hintLine = hintLine + item + " ";
			    }
		    } else {
			    auto iter = helpMap.find(command.toString());
			    if (iter != helpMap.end()) {
				    std::string helpLine = iter->second.usage;
				    std::vector<std::vector<StringRef>> parsedHelp = parseLine(helpLine, error, partial);
				    for (int i = finishedParameters; i < parsedHelp.back().size(); i++) {
					    hintLine = hintLine + parsedHelp.back()[i].toString() + " ";
				    }
			    } else {
				    return LineNoise::Hint();
			    }
		    }

		    return LineNoise::Hint(hintLine, 90, false);
	    },
	    1000,
	    false);

	state std::string historyFilename;
	try {
		historyFilename = joinPath(getUserHomeDirectory(), ".fdbcli_history");
		linenoise.historyLoad(historyFilename);
	} catch (Error& e) {
		TraceEvent(SevWarnAlways, "ErrorLoadingCliHistory")
		    .error(e)
		    .detail("Filename", historyFilename.empty() ? "<unknown>" : historyFilename)
		    .GetLastError();
	}

	state int result = wait(cli(opt, &linenoise));

	if (!historyFilename.empty()) {
		try {
			linenoise.historySave(historyFilename);
		} catch (Error& e) {
			TraceEvent(SevWarnAlways, "ErrorSavingCliHistory")
			    .error(e)
			    .detail("Filename", historyFilename)
			    .GetLastError();
		}
	}

	return result;
}

ACTOR Future<Void> timeExit(double duration) {
	wait(delay(duration));
	fprintf(stderr, "Specified timeout reached -- exiting...\n");
	return Void();
}

int main(int argc, char** argv) {
	platformInit();
	Error::init();
	std::set_new_handler(&platform::outOfMemory);
	uint64_t memLimit = 8LL << 30;
	setMemoryQuota(memLimit);

	registerCrashHandler();

	IKnobCollection::setGlobalKnobCollection(IKnobCollection::Type::CLIENT, Randomize::False, IsSimulated::False);

#ifdef __unixish__
	struct sigaction act;

	// We don't want ctrl-c to quit
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	sigaction(SIGINT, &act, nullptr);
#endif

	CLIOptions opt(argc, argv);
	if (opt.exit_code != -1)
		return opt.exit_code;

	if (opt.trace) {
		if (opt.traceDir.empty())
			setNetworkOption(FDBNetworkOptions::TRACE_ENABLE);
		else
			setNetworkOption(FDBNetworkOptions::TRACE_ENABLE, StringRef(opt.traceDir));

		if (!opt.traceFormat.empty()) {
			setNetworkOption(FDBNetworkOptions::TRACE_FORMAT, StringRef(opt.traceFormat));
		}
		setNetworkOption(FDBNetworkOptions::ENABLE_SLOW_TASK_PROFILING);
	}
	initHelp();

	// deferred TLS options
	if (opt.tlsCertPath.size()) {
		try {
			setNetworkOption(FDBNetworkOptions::TLS_CERT_PATH, opt.tlsCertPath);
		} catch (Error& e) {
			fprintf(stderr, "ERROR: cannot set TLS certificate path to `%s' (%s)\n", opt.tlsCertPath.c_str(), e.what());
			return 1;
		}
	}

	if (opt.tlsCAPath.size()) {
		try {
			setNetworkOption(FDBNetworkOptions::TLS_CA_PATH, opt.tlsCAPath);
		} catch (Error& e) {
			fprintf(stderr, "ERROR: cannot set TLS CA path to `%s' (%s)\n", opt.tlsCAPath.c_str(), e.what());
			return 1;
		}
	}
	if (opt.tlsKeyPath.size()) {
		try {
			if (opt.tlsPassword.size())
				setNetworkOption(FDBNetworkOptions::TLS_PASSWORD, opt.tlsPassword);

			setNetworkOption(FDBNetworkOptions::TLS_KEY_PATH, opt.tlsKeyPath);
		} catch (Error& e) {
			fprintf(stderr, "ERROR: cannot set TLS key path to `%s' (%s)\n", opt.tlsKeyPath.c_str(), e.what());
			return 1;
		}
	}
	if (opt.tlsVerifyPeers.size()) {
		try {
			setNetworkOption(FDBNetworkOptions::TLS_VERIFY_PEERS, opt.tlsVerifyPeers);
		} catch (Error& e) {
			fprintf(
			    stderr, "ERROR: cannot set TLS peer verification to `%s' (%s)\n", opt.tlsVerifyPeers.c_str(), e.what());
			return 1;
		}
	}

	try {
		setNetworkOption(FDBNetworkOptions::DISABLE_CLIENT_STATISTICS_LOGGING);
	} catch (Error& e) {
		fprintf(stderr, "ERROR: cannot disable logging client related information (%s)\n", e.what());
		return 1;
	}

	if (opt.debugTLS) {
#ifndef TLS_DISABLED
		// Backdoor into NativeAPI's tlsConfig, which is where the above network option settings ended up.
		extern TLSConfig tlsConfig;
		printf("TLS Configuration:\n");
		printf("\tCertificate Path: %s\n", tlsConfig.getCertificatePathSync().c_str());
		printf("\tKey Path: %s\n", tlsConfig.getKeyPathSync().c_str());
		printf("\tCA Path: %s\n", tlsConfig.getCAPathSync().c_str());
		try {
			LoadedTLSConfig loaded = tlsConfig.loadSync();
			printf("\tPassword: %s\n", loaded.getPassword().empty() ? "Not configured" : "Exists, but redacted");
			printf("\n");
			loaded.print(stdout);
		} catch (Error& e) {
			fprintf(stderr, "ERROR: %s (%d)\n", e.what(), e.code());
			printf("Use --log and look at the trace logs for more detailed information on the failure.\n");
			return 1;
		}
#else
		printf("This fdbcli was built with TLS disabled.\n");
#endif
		return 0;
	}

	try {
		// Note: refactoring fdbcli, in progress
		API->selectApiVersion(FDB_API_VERSION);
		API->setupNetwork();
		Future<int> cliFuture = runCli(opt);
		Future<Void> timeoutFuture = opt.exit_timeout ? timeExit(opt.exit_timeout) : Never();
		auto f = stopNetworkAfter(success(cliFuture) || timeoutFuture);
		runNetwork();

		if (cliFuture.isReady()) {
			return cliFuture.get();
		} else {
			return 1;
		}
	} catch (Error& e) {
		fprintf(stderr, "ERROR: %s (%d)\n", e.what(), e.code());
		return 1;
	}
}
