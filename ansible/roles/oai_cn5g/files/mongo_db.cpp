#include "mongo_db.hpp"

#include <iostream>
#include <chrono>
#include <thread>
#include <functional>
#include <spdlog/spdlog.h>

#include "AccessAndMobilitySubscriptionData.h"
#include "AuthenticationSubscription.h"
#include "ProblemDetails.h"
#include "SdmSubscription.h"
#include "logger.hpp"
#include "udr_config.hpp"

#include <boost/algorithm/string.hpp>

using namespace oai::udr::app;
using namespace oai::udr::model;
using namespace oai::udr::config;
using namespace oai::model::common;

extern udr_config udr_cfg;

mongo_db::mongo_db(udr_event& ev)
    : database_wrapper<mongo_db>(), m_event_sub(ev), m_db_connection_status() {
  is_db_connection_active = false;
  start_event_connection_handling();
}

//------------------------------------------------------------------------------
mongo_db::~mongo_db() {
  if (db_connection_event.connected()) db_connection_event.disconnect();
  close_connection();
}

//------------------------------------------------------------------------------
bool mongo_db::initialize() {
  return true;
}

//------------------------------------------------------------------------------
bool mongo_db::connect(uint32_t num_retries) {
  Logger::udr_db().debug("Connecting to MongoDB");

  int i = 0;
  while (i < num_retries) {
    try {
      // Try to connect to MongoDB

      mongo_client = mongocxx::client{mongocxx::uri{
          "mongodb://" + udr_cfg.db_conf.user + ":" + udr_cfg.db_conf.pass +
          "@" + udr_cfg.db_conf.server + ":" +
          std::to_string(udr_cfg.db_conf.port)}};

      // Check if connection to MongoDB works
      bsoncxx::builder::stream::document ping;
      ping << "ping" << 1;
      auto db = mongo_client[udr_cfg.db_conf.db_name.c_str()];
      db.run_command(ping.view());

      Logger::udr_db().info("Connected to MongoDB");
      set_db_connection_status(true);
      Logger::udr_db().info("Mongo client created successfully");

      return true;
    } catch (const mongocxx::exception& ex) {
      std::cout << "Mongo client URI: " << mongo_client.uri().to_string()
                << std::endl;
      Logger::udr_db().error(
          "An error occurred when connecting to MongoDB (%s), retry ...",
          ex.what());
      i++;
      set_db_connection_status(false);
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }

  Logger::udr_db().error(
      "Failed to connect to MongoDB after %d retries", num_retries);
  return false;
}

//------------------------------------------------------------------------------
bool mongo_db::close_connection() {
  Logger::udr_db().debug("Close the connection with MongoDB");
  // No need to explicitly close the MongoDB connection
  set_db_connection_status(false);
  return true;
}

//------------------------------------------------------------------------------
void mongo_db::set_db_connection_status(bool status) {
  std::unique_lock lock(m_db_connection_status);
  is_db_connection_active = status;
}

//------------------------------------------------------------------------------
bool mongo_db::get_db_connection_status() const {
  std::shared_lock lock(m_db_connection_status);
  return is_db_connection_active;
}

//---------------------------------------------------------------------------------------------
void mongo_db::start_event_connection_handling() {
  // create a time point representing the current time
  auto now = std::chrono::system_clock::now();

  // convert the time point to milliseconds
  uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();

  struct itimerspec its;
  its.it_value.tv_sec  = udr_cfg.db_conf.connection_timeout;  // seconds
  its.it_value.tv_nsec = 0;  // 100 * 1000 * 1000; //100ms
  const uint64_t interval =
      its.it_value.tv_sec * 1000 +
      its.it_value.tv_nsec / 1000000;  // convert sec, nsec to msec

  db_connection_event = m_event_sub.subscribe_task_nf_heartbeat(
      std::bind(
          &mongo_db::trigger_connection_handling_procedure, this,
          std::placeholders::_1),
      interval, ms + interval);
}
//---------------------------------------------------------------------------------------------
void mongo_db::trigger_connection_handling_procedure(uint64_t ms) {
  _unused(ms);
  std::time_t current_time =
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  Logger::udr_db().debug(
      "DB Connection handling, current time: %s", std::ctime(&current_time));

  try {
    if (mongo_client) {
      // mongo_client.reset(client);
      bsoncxx::builder::stream::document ping;
      ping << "ping" << 1;
      auto db = mongo_client[udr_cfg.db_conf.db_name.c_str()];
      db.run_command(ping.view());
      return;
    }
  } catch (const std::exception& e) {
    set_db_connection_status(false);
    Logger::udr_db().warn(
        "Could not establish the connection to the DB, reason: %s", e.what());
  }

  // If couldn't connect to the DB
  // Reset the connection and try again
  close_connection();
  initialize();
  if (!connect(MAX_CONNECTION_RETRY))
    Logger::udr_db().warn("Could not establish the connection to the DB");
}

//------------------------------------------------------------------------------
bool mongo_db::insert_authentication_subscription(
    const std::string& id,
    const oai::udr::model::AuthenticationSubscription& auth_subscription,
    nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info(
        "The connection to the MongoDB is currently inactive");
    return false;
  }
  // Select the appropriate database and collection
  mongocxx::database db     = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  mongocxx::collection coll = db["AuthenticationSubscription"];
  bsoncxx::builder::stream::document filter_builder{};
  filter_builder << "ueid" << id;

  mongocxx::options::find opts{};
  opts.limit(1);

  try {
    auto cursor = coll.find_one(filter_builder.view(), opts);

    if (cursor) {
      Logger::udr_db().error("AuthenticationSubscription existed!");
      // Existed
      return false;
    }

    bsoncxx::builder::stream::document auth_subscription_builder{};
    auth_subscription_builder << "ueid" << id << "authenticationMethod"
                              << auth_subscription.getAuthenticationMethod();

    if (auth_subscription.encPermanentKeyIsSet()) {
      auth_subscription_builder << "encPermanentKey"
                                << auth_subscription.getEncPermanentKey();
    }

    if (auth_subscription.protectionParameterIdIsSet()) {
      auth_subscription_builder << "protectionParameterId"
                                << auth_subscription.getProtectionParameterId();
    }

    if (auth_subscription.authenticationManagementFieldIsSet()) {
      auth_subscription_builder
          << "authenticationManagementField"
          << auth_subscription.getAuthenticationManagementField();
    }

    if (auth_subscription.algorithmIdIsSet()) {
      auth_subscription_builder << "algorithmId"
                                << auth_subscription.getAlgorithmId();
    }

    if (auth_subscription.encOpcKeyIsSet()) {
      auth_subscription_builder << "encOpcKey"
                                << auth_subscription.getEncOpcKey();
    }

    if (auth_subscription.encTopcKeyIsSet()) {
      auth_subscription_builder << "encTopcKey"
                                << auth_subscription.getEncTopcKey();
    }

    if (auth_subscription.n5gcAuthMethodIsSet()) {
      auth_subscription_builder << "n5gcAuthMethod"
                                << auth_subscription.getN5gcAuthMethod();
    }

    if (auth_subscription.supiIsSet()) {
      auth_subscription_builder << "supi" << auth_subscription.getSupi();
    }

    if (auth_subscription.sequenceNumberIsSet()) {
      const auto& sequence_number   = auth_subscription.getSequenceNumber();
      int64_t sequence_number_value = std::stoll(sequence_number.getSqn());
      bsoncxx::builder::stream::document sequence_number_builder{};
      sequence_number_builder << "sequenceNumber"
                              << bsoncxx::types::b_int64{sequence_number_value};
      // auth_subscription_builder << sequence_number_builder;
    }

    bsoncxx::document::value auth_subscription_doc =
        auth_subscription_builder << bsoncxx::builder::stream::finalize;

    coll.insert_one(auth_subscription_doc.view());

    to_json(json_data, auth_subscription);

    Logger::udr_db().debug(
        "AuthenticationSubscription POST: %s", json_data.dump().c_str());

    return true;
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while insert authentication subscription in MongoDB: %s",
        e.what());
    return false;
  }
}

bool mongo_db::delete_authentication_subscription(const std::string& id) {
  // Select the appropriate database and collection
  mongocxx::database db     = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  mongocxx::collection coll = db["AuthenticationSubscription"];

  // Construct the query document
  bsoncxx::document::value query_value = bsoncxx::builder::stream::document{}
                                         << "ueid" << id
                                         << bsoncxx::builder::stream::finalize;
  bsoncxx::document::view_or_value query = query_value.view();

  try {
    // Perform the delete operation
    auto result = coll.delete_one(query);

    if (!result) {
      std::cerr << "Failed to delete document from MongoDB" << std::endl;
      return false;
    }

    if (result->deleted_count() == 0) {
      std::cerr << "No document found with the given ID" << std::endl;
      return false;
    }

    std::cout << "Deleted " << result->deleted_count()
              << " document(s) from MongoDB" << std::endl;

    return true;
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while delete authentication subscription from MongoDB: %s",
        e.what());
    return false;
  }
}

bool mongo_db::query_authentication_subscription(
    const std::string& id, nlohmann::json& json_data) {
  // Check the connection with DB first

  if (!get_db_connection_status()) {
    Logger::udr_db().info(
        "The connection to the MongoDB is currently inactive");
    return false;
  }

  Logger::udr_db().info("Query Authentication Subscription");

  // Get the database and collection
  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["AuthenticationSubscription"];

  // Build the query
  auto query = bsoncxx::builder::stream::document{}
               << "ueid" << id << bsoncxx::builder::stream::finalize;

  try {
    // Execute the query and get the result
    bsoncxx::stdx::optional<bsoncxx::document::value> result = coll.find_one(
        bsoncxx::builder::stream::document{}
        << "ueid" << id << bsoncxx::builder::stream::finalize);

    if (result) {
      bsoncxx::document::view view = result->view();

      AuthenticationSubscription authentication_subscription = {};
      from_json(
          nlohmann::json::parse(bsoncxx::to_json(view)),
          authentication_subscription);

      to_json(json_data, authentication_subscription);

      return true;
    } else {
      Logger::udr_db().error(
          "AuthenticationSubscription no data！ Query filter: %s",
          bsoncxx::to_json(query.view()).c_str());

      return false;
    }
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while query authentication subscription from MongoDB: %s",
        e.what());
    return false;
  }
}

//------------------------------------------------------------------------------

bool mongo_db::update_authentication_subscription(
    const std::string& ue_id,
    const std::vector<oai::model::common::PatchItem>& patchItem,
    nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  // Get the database and collection
  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["AuthenticationSubscription"];

  auto filter = bsoncxx::builder::stream::document{}
                << "ueid" << ue_id << bsoncxx::builder::stream::finalize;

  try {
    bsoncxx::stdx::optional<bsoncxx::document::value> result =
        coll.find_one(filter.view());

    if (result) {
      bsoncxx::document::view view = result->view();

      for (const auto& item : patchItem) {
        if (item.getOp().getEnumValue() ==
                PatchOperation_anyOf::ePatchOperation_anyOf::REPLACE &&
            item.valueIsSet()) {
          SequenceNumber sequenceNumber;
          nlohmann::json::parse(item.getValue().c_str()).get_to(sequenceNumber);

          bsoncxx::document::value sequenceNumberValue =
              bsoncxx::from_json(item.getValue());
          bsoncxx::document::view sequenceNumberView =
              sequenceNumberValue.view();

          std::string sequenceNumberJson = bsoncxx::to_json(sequenceNumberView);

          bsoncxx::builder::stream::document updateBuilder{};
          updateBuilder << "$set" << bsoncxx::builder::stream::open_document;
          updateBuilder << "sequenceNumber" << sequenceNumberView;
          updateBuilder << bsoncxx::builder::stream::close_document;

          auto update = updateBuilder << bsoncxx::builder::stream::finalize;

          auto updateResult = coll.update_one(filter.view(), update.view());
          if (!updateResult) {
            Logger::udr_db().error(
                "Failed to update AuthenticationSubscription");
            return false;
          }
        }

        nlohmann::json tmp_j;
        to_json(tmp_j, item);
        json_data += tmp_j;
      }

      Logger::udr_db().info(
          "AuthenticationSubscription PATCH: %s", json_data.dump().c_str());
      bool query_result = query_authentication_subscription(ue_id, json_data);
      if (!query_result) {
        Logger::udr_db().error(
            "Failed to retrieve updated authentication subscription data");
        return false;
      }

      return true;
    } else {
      Logger::udr_db().error(
          "AuthenticationSubscription not found for ueid: %s", ue_id.c_str());
      return false;
    }
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while update authentication subscription in MongoDB: %s",
        e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool mongo_db::query_am_data(
    const std::string& ue_id, const std::string& serving_plmn_id,
    nlohmann::json& json_data) {
  // Establish MongoDB connection
  if (!get_db_connection_status()) {
    Logger::udr_db().info(
        "The connection to the MongoDB is currently inactive");
    return false;
  }

  // Get the database and collection
  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["AccessAndMobilitySubscriptionData"];

  // Construct the MongoDB query
  bsoncxx::builder::stream::document query_builder{};
  query_builder << "ueid" << ue_id << "servingPlmnid" << serving_plmn_id;
  auto query = query_builder.view();

  try {
    auto result = coll.find_one(query);
    if (result) {
      oai::udr::model::AccessAndMobilitySubscriptionData subscription_data = {};

      const bsoncxx::document::view row = result.value().view();

      from_json(
          nlohmann::json::parse(bsoncxx::to_json(row)), subscription_data);
      to_json(json_data, subscription_data);

      Logger::udr_db().debug(
          "AccessAndMobilitySubscriptionData Get: %s",
          json_data.dump().c_str());
    } else {
      // Handle query failure
      Logger::udr_db().error("Failed to query AM Data from MongoDB");
      return false;
    }
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while query AM Data from MongoDB: %s", e.what());
    return false;
  } catch (const std::exception& e) {
    Logger::udr_db().error(
        "Exception while query AM Data from MongoDB: %s", e.what());
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool mongo_db::create_amf_context_3gpp(
    const std::string& ue_id,
    Amf3GppAccessRegistration& amf3GppAccessRegistration) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  bsoncxx::builder::stream::document filter_builder;
  filter_builder << "ueid" << ue_id;

  // Select the appropriate database and collection
  mongocxx::database db = mongo_client[udr_cfg.db_conf.db_name.c_str()];

  try {
    auto find_opts = mongocxx::options::find{};
    auto document  = db["Amf3GppAccessRegistration"].find_one(
        filter_builder.view(), find_opts);

    bsoncxx::builder::stream::document update_doc;
    update_doc << "$set" << bsoncxx::builder::stream::open_document;
    update_doc << "amfInstanceId"
               << amf3GppAccessRegistration.getAmfInstanceId();

    if (amf3GppAccessRegistration.supportedFeaturesIsSet()) {
      update_doc << "supportedFeatures"
                 << amf3GppAccessRegistration.getSupportedFeatures();
    }

    if (amf3GppAccessRegistration.purgeFlagIsSet()) {
      update_doc << "purgeFlag"
                 << (amf3GppAccessRegistration.isPurgeFlag() ? 1 : 0);
    }

    if (amf3GppAccessRegistration.peiIsSet()) {
      update_doc << "pei" << amf3GppAccessRegistration.getPei();
    }

    if (amf3GppAccessRegistration.pcscfRestorationCallbackUriIsSet()) {
      update_doc << "pcscfRestorationCallbackUri"
                 << amf3GppAccessRegistration.getPcscfRestorationCallbackUri();
    }

    if (amf3GppAccessRegistration.initialRegistrationIndIsSet()) {
      update_doc << "initialRegistrationInd"
                 << (amf3GppAccessRegistration.isInitialRegistrationInd() ? 1 :
                                                                            0);
    }

    if (amf3GppAccessRegistration.drFlagIsSet()) {
      update_doc << "drFlag" << (amf3GppAccessRegistration.isDrFlag() ? 1 : 0);
    }

    if (amf3GppAccessRegistration.urrpIndicatorIsSet()) {
      update_doc << "urrpIndicator"
                 << (amf3GppAccessRegistration.isUrrpIndicator() ? 1 : 0);
    }

    if (amf3GppAccessRegistration.amfEeSubscriptionIdIsSet()) {
      update_doc << "amfEeSubscriptionId"
                 << amf3GppAccessRegistration.getAmfEeSubscriptionId();
    }

    if (amf3GppAccessRegistration.ueSrvccCapabilityIsSet()) {
      update_doc << "ueSrvccCapability"
                 << (amf3GppAccessRegistration.isUeSrvccCapability() ? 1 : 0);
    }

    if (amf3GppAccessRegistration.registrationTimeIsSet()) {
      update_doc << "registrationTime"
                 << amf3GppAccessRegistration.getRegistrationTime();
    }

    if (amf3GppAccessRegistration.noEeSubscriptionIndIsSet()) {
      update_doc << "noEeSubscriptionInd"
                 << (amf3GppAccessRegistration.isNoEeSubscriptionInd() ? 1 : 0);
    }
    if (amf3GppAccessRegistration.imsVoPsIsSet()) {
      nlohmann::json j;
      to_json(j, amf3GppAccessRegistration.getImsVoPs());
      update_doc << "imsVoPs" << j.dump();
    }

    if (amf3GppAccessRegistration.amfServiceNameDeregIsSet()) {
      nlohmann::json j;
      to_json(j, amf3GppAccessRegistration.getAmfServiceNameDereg());
      update_doc << "amfServiceNameDereg" << j.dump();
    }
    if (amf3GppAccessRegistration.amfServiceNamePcscfRestIsSet()) {
      nlohmann::json j;
      to_json(j, amf3GppAccessRegistration.getAmfServiceNamePcscfRest());
      update_doc << "amfServiceNamePcscfRest" << j.dump();
    }

    if (amf3GppAccessRegistration.backupAmfInfoIsSet()) {
      std::vector<BackupAmfInfo> backupamfinfo =
          amf3GppAccessRegistration.getBackupAmfInfo();
      auto arr_builder = bsoncxx::builder::stream::array{};
      for (int i = 0; i < backupamfinfo.size(); i++) {
        nlohmann::json json_obj = backupamfinfo[i];
        auto tmp                = bsoncxx::from_json(json_obj.dump());
        arr_builder << tmp.view();
      }
      auto arr = arr_builder << bsoncxx::types::b_null{}
                             << bsoncxx::builder::stream::finalize;
      update_doc << "backupAmfInfo" << arr;
    }

    if (amf3GppAccessRegistration.epsInterworkingInfoIsSet()) {
      nlohmann::json j;
      to_json(j, amf3GppAccessRegistration.getEpsInterworkingInfo());
      update_doc << "epsInterworkingInfo" << j.dump();
    }
    if (amf3GppAccessRegistration.vgmlcAddressIsSet()) {
      nlohmann::json j;
      to_json(j, amf3GppAccessRegistration.getVgmlcAddress());
      update_doc << "vgmlcAddress" << j.dump();
    }

    if (amf3GppAccessRegistration.contextInfoIsSet()) {
      nlohmann::json j;
      to_json(j, amf3GppAccessRegistration.getContextInfo());
      update_doc << "contextInfo" << j.dump();
    }
    nlohmann::json j;
    to_json(j, amf3GppAccessRegistration.getGuami());
    update_doc << "guami" << j.dump();

    to_json(j, amf3GppAccessRegistration.getRatType());
    update_doc << "ratType" << j.dump();

    update_doc << bsoncxx::builder::stream::close_document;

    if (document) {
      auto result = db["Amf3GppAccessRegistration"].update_one(
          filter_builder.view(), update_doc.view());
      if (!result) {
        Logger::udr_db().error(
            "MongoDB update_one failure! Query: %s",
            bsoncxx::to_json(update_doc.view()).c_str());
        return false;
      }
      return true;
    } else {
      Logger::udr_db().error(
          "MongoDB Document %S not found! Query could not be submitted: %s",
          bsoncxx::to_json(filter_builder.view()),
          bsoncxx::to_json(update_doc.view()));
      return false;
    }
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while create AMF context in MongoDB: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool mongo_db::query_amf_context_3gpp(
    const std::string& ue_id, nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  auto db         = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto collection = db["Amf3GppAccessRegistration"];
  bsoncxx::builder::stream::document filter_builder;
  filter_builder << "ueid" << ue_id;
  auto filter = filter_builder.view();

  try {
    auto cursor = collection.find_one(filter);

    // auto document = result.value();
    if (cursor) {
      oai::udr::model::Amf3GppAccessRegistration amf3gppaccessregistration = {};
      const bsoncxx::document::view row = cursor.value().view();

      from_json(
          nlohmann::json::parse(bsoncxx::to_json(row)),
          amf3gppaccessregistration);
      to_json(json_data, amf3gppaccessregistration);

      // json_data = amf3gppaccessregistration.to_json();
      return true;
    } else {
      Logger::udr_db().info(
          "AMF 3GPP Access Registration for UE ID %s not found in MongoDB",
          ue_id.c_str());
      return false;
    }
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while query AMF context from MongoDB: %s", e.what());
    return false;
  } catch (const std::exception& e) {
    Logger::udr_db().error(
        "Exception while query sm data from MongoDB: %s", e.what());
    return false;
  }
}
//------------------------------------------------------------------------------
bool mongo_db::insert_authentication_status(
    const std::string& ue_id, const oai::udr::model::AuthEvent& authEvent,
    nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  // Get the database and collection
  auto db         = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto collection = db["AuthenticationStatus"];
  auto filter     = bsoncxx::builder::stream::document{}
                << "ueid" << ue_id << bsoncxx::builder::stream::finalize;

  try {
    bsoncxx::stdx::optional<bsoncxx::document::value> result =
        collection.find_one(filter.view());

    bsoncxx::builder::stream::document documentBuilder{};

    documentBuilder << "ueid" << ue_id;
    documentBuilder << "nfInstanceId" << authEvent.getNfInstanceId();
    documentBuilder << "success" << (authEvent.isSuccess() ? true : false);
    documentBuilder << "timeStamp" << authEvent.getTimeStamp();
    documentBuilder << "authType" << authEvent.getAuthType();
    documentBuilder << "servingNetworkName"
                    << authEvent.getServingNetworkName();

    if (authEvent.authRemovalIndIsSet()) {
      documentBuilder << "authRemovalInd"
                      << (authEvent.isAuthRemovalInd() ? true : false);
    }

    auto document = documentBuilder << bsoncxx::builder::stream::finalize;

    if (result) {
      auto updateResult = collection.update_one(
          filter.view(),
          bsoncxx::builder::basic::make_document(
              bsoncxx::builder::basic::kvp("$set", document.view())));
      if (!updateResult) {
        Logger::udr_db().error("Failed to update AuthenticationStatus");
        return false;
      }
    } else {
      auto insertResult = collection.insert_one(document.view());
      if (!insertResult) {
        Logger::udr_db().error("Failed to insert AuthenticationStatus");
        return false;
      }
    }

    nlohmann::json tmp = {};
    to_json(tmp, authEvent);
    Logger::udr_db().info("AuthenticationStatus PUT: %s", tmp.dump().c_str());

    return true;

  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while insert authentication status in MongoDB: %s",
        e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool mongo_db::delete_authentication_status(const std::string& ue_id) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  mongocxx::database db     = mongo_client["oai_ab_mongo"];
  mongocxx::collection coll = db["AuthenticationStatus"];

  bsoncxx::builder::stream::document filter_builder;
  filter_builder
      << "ueid"
      << ue_id;  // Create a filter document for matching the "ueid" field

  try {
    auto result = coll.delete_one(
        filter_builder.view());  // Delete the document matching the filter
    if (result) {
      if (result->deleted_count() > 0) {
        Logger::udr_db().debug("AuthenticationStatus DELETE - successful");

        return true;
      } else {
        Logger::udr_db().info(
            "No document found with ueid '%s'", ue_id.c_str());
        return false;
      }
    } else {
      Logger::udr_db().error("Failed to delete document in MongoDB");
      return false;
    }
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while delete authentication status from MongoDB: %s",
        e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool mongo_db::query_authentication_status(
    const std::string& ue_id, nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info(
        "The connection to the MongoDB is currently inactive");
    return false;
  }

  Logger::udr_db().info("Query Authentication Status");

  // Get the database and collection
  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["AuthenticationStatus"];

  // Build the query
  auto query = bsoncxx::builder::stream::document{}
               << "ueid" << ue_id << bsoncxx::builder::stream::finalize;

  try {
    // Execute the query and get the result
    bsoncxx::stdx::optional<bsoncxx::document::value> result =
        coll.find_one(query.view());

    // Check if the result is not empty
    if (result) {
      // Convert the result object to a JSON string
      std::string result_str = bsoncxx::to_json(result->view());

      // Log the result using the Logger::udr_db().info() method
      Logger::udr_db().info("MongoDB Result: %s", result_str.c_str());

      bsoncxx::document::view view    = result->view();
      AuthEvent authentication_status = {};

      if (view["nfInstanceId"]) {
        authentication_status.setNfInstanceId(
            std::string{view["nfInstanceId"].get_string().value});
      }

      if (view["success"]) {
        bool success = view["success"].get_bool().value;
        authentication_status.setSuccess(success);
      }

      if (view["timeStamp"]) {
        authentication_status.setTimeStamp(
            std::string{view["timeStamp"].get_string().value});
      }

      if (view["authType"]) {
        authentication_status.setAuthType(
            std::string{view["authType"].get_string().value});
      }

      if (view["servingNetworkName"]) {
        authentication_status.setServingNetworkName(
            std::string{view["servingNetworkName"].get_string().value});
      }

      if (view["authRemovalInd"]) {
        bool authRemovalInd = view["authRemovalInd"].get_bool().value;
        authentication_status.setAuthRemovalInd(authRemovalInd);
      }

      to_json(json_data, authentication_status);
      return true;
    } else {
      Logger::udr_db().error(
          "AuthenticationStatus no data！ Query filter: %s",
          bsoncxx::to_json(query.view()).c_str());
      return false;
    }
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while query authentication data from MongoDB: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool mongo_db::query_sdm_subscription(
    const std::string& ue_id, const std::string& subs_id,
    nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  // Select the appropriate database and collection
  mongocxx::database db     = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  mongocxx::collection coll = db["SdmSubscriptions"];
  bsoncxx::builder::stream::document filter_builder;
  filter_builder << "ueid" << ue_id << "subsId" << subs_id;
  auto filter = filter_builder.view();

  try {
    auto cursor = coll.find_one(filter);

    if (cursor) {
      auto doc                                          = cursor->view();
      oai::udr::model::SdmSubscription SdmSubscriptions = {};
      // AuthenticationSubscription authentication_subscription = {};

      if (doc["nfInstanceId"]) {
        SdmSubscriptions.setNfInstanceId(
            static_cast<std::string>(doc["nfInstanceId"].get_string().value));
      }

      if (doc["implicitUnsubscribe"]) {
        if (static_cast<std::string>(doc["implicitUnsubscribe"].get_string().value) != "0")
          SdmSubscriptions.setImplicitUnsubscribe(true);
        else
          SdmSubscriptions.setImplicitUnsubscribe(false);
      }

      if (doc["expires"]) {
        SdmSubscriptions.setExpires(
            static_cast<std::string>(doc["expires"].get_string().value));
      }

      if (doc["callbackReference"]) {
        SdmSubscriptions.setCallbackReference(
            static_cast<std::string>(doc["callbackReference"].get_string().value));
      }

      if (doc["amfServiceName"]) {
        oai::model::nrf::ServiceName amfservicename;
        nlohmann::json::parse(doc["amfServiceName"].get_string().value)
            .get_to(amfservicename);
        SdmSubscriptions.setAmfServiceName(amfservicename);
      }

      if (doc["monitoredResourceUris"]) {
        std::vector<std::string> monitoredresourceuris;
        nlohmann::json::parse(doc["monitoredResourceUris"].get_string().value)
            .get_to(monitoredresourceuris);
        SdmSubscriptions.setMonitoredResourceUris(monitoredresourceuris);
      }

      if (doc["singleNssai"]) {
        Snssai singlenssai;
        nlohmann::json::parse(doc["singleNssai"].get_string().value)
            .get_to(singlenssai);
        SdmSubscriptions.setSingleNssai(singlenssai);
      }

      if (doc["dnn"]) {
        SdmSubscriptions.setDnn(static_cast<std::string>(doc["dnn"].get_string().value));
      }

      if (doc["subscriptionId"]) {
        SdmSubscriptions.setSubscriptionId(
            static_cast<std::string>(doc["subscriptionId"].get_string().value));
      }

      if (doc["plmnId"]) {
        PlmnId plmnid;
        nlohmann::json::parse(doc["plmnId"].get_string().value).get_to(plmnid);
        SdmSubscriptions.setPlmnId(plmnid);
      }

      if (doc["immediateReport"]) {
        if (static_cast<std::string>(doc["immediateReport"].get_string().value) != "0")
          SdmSubscriptions.setImmediateReport(true);
        else
          SdmSubscriptions.setImmediateReport(false);
      }

      if (doc["report"]) {
        SubscriptionDataSets report;
        nlohmann::json::parse(doc["report"].get_string().value).get_to(report);
        SdmSubscriptions.setReport(report);
      }

      if (doc["subscriptionId"]) {
        SdmSubscriptions.setSubscriptionId(
            static_cast<std::string>(doc["subscriptionId"].get_string().value));
      }
      if (doc["contextInfo"]) {
        ContextInfo contextInfo;
        nlohmann::json::parse(doc["contextInfo"].get_string().value)
            .get_to(contextInfo);
        SdmSubscriptions.setContextInfo(contextInfo);
      }

      // Convert SdmSubscriptions to json
      nlohmann::json sdmSubscriptionsJson = SdmSubscriptions;

      // Assign the converted json to the output json_data
      json_data = sdmSubscriptionsJson;

      Logger::udr_db().debug(
          "Successfully queried SDM subscription from MongoDB: UE ID={}, "
          "Subscription ID={}",
          ue_id, subs_id);
      return true;
    } else {
      Logger::udr_db().info(
          "Failed to query SDM subscription from MongoDB: UE ID={}, "
          "Subscription "
          "ID={}",
          ue_id, subs_id);
      return false;
    }
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while query sdm subscription from MongoDB: %s", e.what());
    return false;
  }
}
//------------------------------------------------------------------------------
bool mongo_db::delete_sdm_subscription(
    const std::string& ue_id, const std::string& subs_id) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info(
        "The connection to the MongoDB is currently inactive");
    return false;
  }

  // Select the appropriate database and collection
  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["SdmSubscriptions"];
  bsoncxx::builder::stream::document filter_builder;
  filter_builder << "ueid" << ue_id << "subsId" << subs_id;
  bsoncxx::document::view_or_value filter = filter_builder.view();

  try {
    auto result = coll.delete_one(filter);

    if (!result || result->deleted_count() == 0) {
      Logger::udr_db().error(
          "Failed to delete document from MongoDB: ueid='%s' subsId='%s'",
          ue_id.c_str(), subs_id.c_str());
      return false;
    }
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while delete sdm subscription from MongoDB: %s", e.what());
    return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool mongo_db::update_sdm_subscription(
    const std::string& ue_id, const std::string& subs_id,
    oai::udr::model::SdmSubscription& sdmSubscription,
    nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  // Select the appropriate database and collection
  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["SdmSubscriptions"];
  // Prepare filter for update
  bsoncxx::builder::stream::document filter;
  filter << "ueid" << bsoncxx::types::b_utf8{ue_id} << "subsId"
         << bsoncxx::types::b_utf8{subs_id};

  // Prepare update document
  bsoncxx::builder::stream::document update;
  update << "$set" << bsoncxx::builder::stream::open_document << "nfInstanceId"
         << sdmSubscription.getNfInstanceId() << "implicitUnsubscribe"
         << (sdmSubscription.implicitUnsubscribeIsSet() ?
                 (sdmSubscription.isImplicitUnsubscribe() ?
                      bsoncxx::types::b_int32{1} :
                      bsoncxx::types::b_int32{0}) :
                 bsoncxx::types::b_int32{0})

         << "expires"
         << (sdmSubscription.expiresIsSet() ?
                 bsoncxx::types::b_utf8{sdmSubscription.getExpires()} :
                 bsoncxx::types::b_utf8{""})
         << "callbackReference"
         << bsoncxx::types::b_utf8{sdmSubscription.getCallbackReference()}
         << "dnn"
         << (sdmSubscription.dnnIsSet() ?
                 bsoncxx::types::b_utf8{sdmSubscription.getDnn()} :
                 bsoncxx::types::b_utf8{""})
         << "subscriptionId"
         << (sdmSubscription.subscriptionIdIsSet() ?
                 bsoncxx::types::b_utf8{sdmSubscription.getSubscriptionId()} :
                 bsoncxx::types::b_utf8{""})
         << "immediateReport"
         << (sdmSubscription.immediateReportIsSet() ?
                 (sdmSubscription.isImmediateReport() ?
                      bsoncxx::types::b_int32{1} :
                      bsoncxx::types::b_int32{0}) :
                 bsoncxx::types::b_int32{0})
         << "supportedFeatures"
         << (sdmSubscription.supportedFeaturesIsSet() ?
                 bsoncxx::types::b_utf8{
                     sdmSubscription.getSupportedFeatures()} :
                 bsoncxx::types::b_utf8{""});

  if (sdmSubscription.amfServiceNameIsSet()) {
    nlohmann::json j;
    to_json(j, sdmSubscription.getAmfServiceName());
    update << "amfServiceName" << bsoncxx::types::b_utf8{j.dump()};
  }
  if (sdmSubscription.singleNssaiIsSet()) {
    nlohmann::json j;
    to_json(j, sdmSubscription.getSingleNssai());
    update << "singleNssai" << bsoncxx::types::b_utf8{j.dump()};
  }
  if (sdmSubscription.plmnIdIsSet()) {
    nlohmann::json j;
    to_json(j, sdmSubscription.getPlmnId());
    update << "plmnId" << bsoncxx::types::b_utf8{j.dump()};
  }
  if (sdmSubscription.reportIsSet()) {
    nlohmann::json j;
    to_json(j, sdmSubscription.getReport());
    update << "report" << bsoncxx::types::b_utf8{j.dump()};
  }
  if (sdmSubscription.contextInfoIsSet()) {
    nlohmann::json j;
    to_json(j, sdmSubscription.getContextInfo());
    update << "contextInfo" << bsoncxx::types::b_utf8{j.dump()};
  }

  try {
    // Execute update query
    auto result = coll.update_one(filter.view(), update.view());

    // Check for update success
    if (result) {
      Logger::udr_db().info(
          "Successfully updated SDM subscription in MongoDB. UE ID: {}, Subs "
          "ID: "
          "{}",
          ue_id, subs_id);
      // Update json_data with updated values
      json_data["nfInstanceId"] = sdmSubscription.getNfInstanceId();
      json_data["implicitUnsubscribe"] =
          sdmSubscription.isImplicitUnsubscribe();
      json_data["expires"]           = sdmSubscription.getExpires();
      json_data["callbackReference"] = sdmSubscription.getCallbackReference();
      json_data["dnn"]               = sdmSubscription.getDnn();
      json_data["subscriptionId"]    = sdmSubscription.getSubscriptionId();
      json_data["immediateReport"]   = sdmSubscription.isImmediateReport();
      json_data["supportedFeatures"] = sdmSubscription.getSupportedFeatures();
      if (sdmSubscription.amfServiceNameIsSet()) {
        json_data["amfServiceName"] = sdmSubscription.getAmfServiceName();
      }
      if (sdmSubscription.singleNssaiIsSet()) {
        json_data["singleNssai"] = sdmSubscription.getSingleNssai();
      }
      if (sdmSubscription.plmnIdIsSet()) {
        json_data["plmnId"] = sdmSubscription.getPlmnId();
      }
      if (sdmSubscription.reportIsSet()) {
        json_data["report"] = sdmSubscription.getReport();
      }
      if (sdmSubscription.contextInfoIsSet()) {
        json_data["contextInfo"] = sdmSubscription.getContextInfo();
      }
      return true;
    } else {
      Logger::udr_db().error(
          "Failed to update SDM subscription in MongoDB. UE ID: {}, Subs ID: "
          "{}",
          ue_id, subs_id);
      return false;
    }
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while update sdm subscription in MongoDB: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool mongo_db::create_sdm_subscriptions(
    const std::string& ue_id, oai::udr::model::SdmSubscription& sdmSubscription,
    nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to the MySQL is currently inactive");
    return false;
  }

  // Select the appropriate database and collection
  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["SdmSubscriptions"];

  bsoncxx::builder::stream::document filter_builder;
  filter_builder << "ueid" << ue_id;
  bsoncxx::document::view_or_value filter = filter_builder.view();

  mongocxx::options::find opts{};
  opts.limit(1);

  try {
    auto result = coll.find_one(filter.view(), opts);
    if (result) {
      bsoncxx::document::element subs_id_elem = result.value().view()["subsId"];
      if (subs_id_elem) {
        int32_t subs_id = subs_id_elem.get_int32().value;
        // sdmSubscription.setSubsId(subs_id);
      }
    }

    bsoncxx::builder::stream::document doc_builder;
    doc_builder << "ueid" << ue_id;
    doc_builder << "nfInstanceId" << sdmSubscription.getNfInstanceId();

    if (sdmSubscription.implicitUnsubscribeIsSet()) {
      doc_builder << "implicitUnsubscribe"
                  << (sdmSubscription.isImplicitUnsubscribe() ? true : false);
    }

    if (sdmSubscription.expiresIsSet()) {
      doc_builder << "expires" << sdmSubscription.getExpires();
    }
    doc_builder << "callbackReference"
                << sdmSubscription.getCallbackReference();

    if (sdmSubscription.dnnIsSet()) {
      doc_builder << "dnn" << sdmSubscription.getDnn();
    }
    if (sdmSubscription.subscriptionIdIsSet()) {
      doc_builder << "subscriptionId" << sdmSubscription.getSubscriptionId();
    }
    if (sdmSubscription.immediateReportIsSet()) {
      doc_builder << "immediateReport" << sdmSubscription.isImmediateReport();
    }
    if (sdmSubscription.supportedFeaturesIsSet()) {
      doc_builder << "supportedFeatures"
                  << sdmSubscription.getSupportedFeatures();
    }
    if (sdmSubscription.amfServiceNameIsSet()) {
      nlohmann::json j;
      to_json(j, sdmSubscription.getAmfServiceName());
      doc_builder << "amfServiceName" << bsoncxx::from_json(j.dump());
    }
    if (sdmSubscription.singleNssaiIsSet()) {
      nlohmann::json j;
      to_json(j, sdmSubscription.getSingleNssai());
      doc_builder << "singleNssai" << bsoncxx::from_json(j.dump());
    }
    if (sdmSubscription.plmnIdIsSet()) {
      nlohmann::json j;
      to_json(j, sdmSubscription.getPlmnId());
      doc_builder << "plmnId" << bsoncxx::from_json(j.dump());
    }
    if (sdmSubscription.reportIsSet()) {
      nlohmann::json j;
      to_json(j, sdmSubscription.getReport());
      doc_builder << "report" << bsoncxx::from_json(j.dump());
    }
    if (sdmSubscription.contextInfoIsSet()) {
      nlohmann::json j;
      to_json(j, sdmSubscription.getContextInfo());
      doc_builder << "contextInfo" << bsoncxx::from_json(j.dump());
    }

    auto MonitoredResourceUris_json =
        nlohmann::json(sdmSubscription.getMonitoredResourceUris());
    doc_builder << "monitoredResourceUris"
                << bsoncxx::from_json(MonitoredResourceUris_json.dump());

    bsoncxx::document::view view = doc_builder.view();
    bsoncxx::document::value doc(view);

    auto cursor = coll.insert_one(doc.view());
    if (cursor) {
      to_json(json_data, sdmSubscription);
      Logger::udr_db().debug(
          "SdmSubscriptions POST: %s", json_data.dump().c_str());
      return true;
    } else {
      Logger::udr_db().error("Failed to insert document into MongoDB");
      return false;
    }
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while create sdm subscription in MongoDB: %s", e.what());
    return false;
  }
}
//------------------------------------------------------------------------------
bool mongo_db::query_sdm_subscriptions(
    const std::string& ue_id, nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  bsoncxx::document::view_or_value query =
      bsoncxx::builder::stream::document{}
      << "ueid" << ue_id << bsoncxx::builder::stream::finalize;

  // Select the appropriate database and collection
  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["SdmSubscriptions"];

  try {
    mongocxx::cursor cursor = coll.find(query.view());
    nlohmann::json j        = {};
    nlohmann::json tmp      = {};

    for (const bsoncxx::document::view& doc : cursor) {
      SdmSubscription sdmsubscriptions = {};
      tmp.clear();

      if (doc["nfInstanceId"]) {
        sdmsubscriptions.setNfInstanceId(
            static_cast<std::string>(doc["nfInstanceId"].get_string().value));
      }
      if (doc["implicitUnsubscribe"]) {
        if (doc["implicitUnsubscribe"].get_bool().value)
          sdmsubscriptions.setImplicitUnsubscribe(true);
        else
          sdmsubscriptions.setImplicitUnsubscribe(false);
      }
      if (doc["expires"]) {
        sdmsubscriptions.setExpires(
            static_cast<std::string>(doc["expires"].get_string().value));
      }
      if (doc["callbackReference"]) {
        sdmsubscriptions.setCallbackReference(
            static_cast<std::string>(doc["callbackReference"].get_string().value));
      }
      if (doc["amfServiceName"]) {
        oai::model::nrf::ServiceName amfservicename;
        nlohmann::json::parse(doc["amfServiceName"].get_string().value)
            .get_to(amfservicename);
        sdmsubscriptions.setAmfServiceName(amfservicename);
      }
      if (doc["monitoredResourceUris"]) {
        std::vector<std::string> monitoredresourceuris;
        nlohmann::json::parse(doc["monitoredResourceUris"].get_string().value)
            .get_to(monitoredresourceuris);
        sdmsubscriptions.setMonitoredResourceUris(monitoredresourceuris);
      }
      if (doc["singleNssai"]) {
        Snssai singlenssai;
        nlohmann::json::parse(doc["singleNssai"].get_string().value)
            .get_to(singlenssai);
        sdmsubscriptions.setSingleNssai(singlenssai);
      }
      if (doc["dnn"]) {
        sdmsubscriptions.setDnn(static_cast<std::string>(doc["dnn"].get_string().value));
      }
      if (doc["subscriptionId"]) {
        sdmsubscriptions.setSubscriptionId(
            static_cast<std::string>(doc["subscriptionId"].get_string().value));
      }
      if (doc["plmnId"]) {
        PlmnId plmnid;
        nlohmann::json::parse(doc["plmnId"].get_string().value).get_to(plmnid);
        sdmsubscriptions.setPlmnId(plmnid);
      }
      if (doc["immediateReport"]) {
        if (doc["immediateReport"].get_bool().value)
          sdmsubscriptions.setImmediateReport(true);
        else
          sdmsubscriptions.setImmediateReport(false);
      }
      if (doc["report"]) {
        SubscriptionDataSets report;
        nlohmann::json::parse(doc["report"].get_string().value).get_to(report);
        sdmsubscriptions.setReport(report);
      }
      if (doc["supportedFeatures"]) {
        sdmsubscriptions.setSupportedFeatures(
            static_cast<std::string>(doc["dnn"].get_string().value));
      }
      if (doc["contextInfo"]) {
        ContextInfo contextInfo;
        nlohmann::json::parse(doc["contextInfo"].get_string().value)
            .get_to(contextInfo);
        sdmsubscriptions.setContextInfo(contextInfo);
      }

      to_json(tmp, sdmsubscriptions);
      j.push_back(tmp);
    }
    json_data = j;
    Logger::udr_db().debug(
        "SdmSubscriptions GET: %s", json_data.dump().c_str());
    return true;
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while query sdm subscription from MongoDB: %s", e.what());
    return false;
  }
}
//------------------------------------------------------------------------------
bool mongo_db::query_sm_data(nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["SessionManagementSubscriptionData"];

  try {
    auto cursor = coll.find({});

    auto row = cursor.begin();
    if (row == cursor.end()) {
      Logger::udr_db().error(
          "Empty document in MongoDB Collection "
          "SessionManagementSubscriptionData");
      return false;
    }

    for (auto&& view : cursor) {
      nlohmann::json j = query_sm_data_helper(view);
      json_data += j;
      Logger::udr_db().debug(
          "SessionManagementSubscriptionData: %s", j.dump().c_str());
    }
    return true;
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while query sm data from MongoDB: %s", e.what());
    return false;
  } catch (const std::exception& e) {
    Logger::udr_db().error(
        "Exception while query sm data from MongoDB: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool mongo_db::query_sm_data(
    const std::string& ue_id, const std::string& serving_plmn_id,
    nlohmann::json& json_data,
    const std::optional<oai::model::common::Snssai>& snssai,
    const std::optional<std::string>& dnn) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  auto db     = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll   = db["SessionManagementSubscriptionData"];
  auto filter = bsoncxx::builder::stream::document{};
  filter << "ueid" << ue_id << "servingPlmnid" << serving_plmn_id;

  if (snssai.value().getSst() > 0) {
    filter << "singleNssai.sst" << snssai.value().getSst();
  }

  if (dnn.has_value()) {
    filter << "dnnConfigurations." + dnn.value()
           << bsoncxx::builder::stream::open_document << "$exists" << true
           << bsoncxx::builder::stream::close_document;
  }

  try {
    auto cursor = coll.find(filter.view());

    auto row = cursor.begin();
    if (row == cursor.end()) {
      Logger::udr_db().error(
          "Empty document in MongoDB: ueid=%s, servingPlmnid=%s", ue_id.c_str(),
          serving_plmn_id.c_str());
      return false;
    }

    for (auto&& view : cursor) {
      nlohmann::json j = query_sm_data_helper(view);
      json_data += j;
      Logger::udr_db().debug(
          "SessionManagementSubscriptionData: %s", j.dump().c_str());
    }
    return true;
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while query sm data from MongoDB: %s", e.what());
    return false;
  } catch (const std::exception& e) {
    Logger::udr_db().error(
        "Exception while query sm data from MongoDB: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
nlohmann::json mongo_db::query_sm_data_helper(
    const bsoncxx::v_noabi::document::view& view) {
  // check if at least one document can be found
  SessionManagementSubscriptionData sessionmanagementsubscriptiondata = {};
  from_json(
      nlohmann::json::parse(bsoncxx::to_json(view)),
      sessionmanagementsubscriptiondata);

  nlohmann::json j;
  to_json(j, sessionmanagementsubscriptiondata);

  return j;
}

//------------------------------------------------------------------------------
bool mongo_db::insert_smf_context_non_3gpp(
    const std::string& ue_id, const int32_t& pdu_session_id,
    const oai::udr::model::SmfRegistration& smfRegistration,
    nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["SmfRegistrations"];

  bsoncxx::builder::stream::document filter_builder{};
  filter_builder << "ueid" << ue_id << "subpduSessionId" << pdu_session_id;
  auto filter = filter_builder.view();

  try {
    auto result = coll.find_one(filter);

    bsoncxx::builder::stream::document document_builder{};
    document_builder << "ueid" << ue_id << "subpduSessionId" << pdu_session_id
                     << "pduSessionId" << smfRegistration.getPduSessionId()
                     << "smfInstanceId" << smfRegistration.getSmfInstanceId()
                     << "pduSessionId" << smfRegistration.getPduSessionId();

    if (smfRegistration.smfSetIdIsSet()) {
      document_builder << "smfSetId" << smfRegistration.getSmfSetId();
    }

    if (smfRegistration.supportedFeaturesIsSet()) {
      document_builder << "supportedFeatures"
                       << smfRegistration.getSupportedFeatures();
    }
    if (smfRegistration.dnnIsSet()) {
      document_builder << "dnn" << smfRegistration.getDnn();
    }

    if (smfRegistration.emergencyServicesIsSet()) {
      document_builder << "emergencyServices"
                       << smfRegistration.isEmergencyServices();
    }

    if (smfRegistration.pcscfRestorationCallbackUriIsSet()) {
      document_builder << "pcscfRestorationCallbackUri"
                       << smfRegistration.getPcscfRestorationCallbackUri();
    }

    if (smfRegistration.pgwFqdnIsSet()) {
      document_builder << "pgwFqdn" << smfRegistration.getPgwFqdn();
    }

    if (smfRegistration.epdgIndIsSet()) {
      document_builder << "epdgInd" << smfRegistration.isEpdgInd();
    }
    if (smfRegistration.deregCallbackUriIsSet()) {
      document_builder << "deregCallbackUri"
                       << smfRegistration.getDeregCallbackUri();
    }

    if (smfRegistration.registrationTimeIsSet()) {
      document_builder << "registrationTime"
                       << smfRegistration.getRegistrationTime();
    }

    if (smfRegistration.registrationReasonIsSet()) {
      auto registrationReason = smfRegistration.getRegistrationReason();
      document_builder << "registrationReason"
                       << bsoncxx::from_json(
                              nlohmann::json(registrationReason).dump());
    }

    if (smfRegistration.contextInfoIsSet()) {
      auto contextInfo = smfRegistration.getContextInfo();
      document_builder << "contextInfo"
                       << bsoncxx::from_json(
                              nlohmann::json(contextInfo).dump());
    }

    auto singleNssai = smfRegistration.getSingleNssai();
    auto plmnId      = smfRegistration.getPlmnId();
    document_builder << "singleNssai"
                     << bsoncxx::from_json(nlohmann::json(singleNssai).dump())
                     << "plmnId"
                     << bsoncxx::from_json(nlohmann::json(plmnId).dump());

    bsoncxx::document::value document_value = document_builder.extract();

    if (result) {
      auto update_result = coll.update_one(
          filter, bsoncxx::builder::stream::document{}
                      << "$set"
                      << bsoncxx::from_json(bsoncxx::to_json(document_value))
                      << bsoncxx::builder::stream::finalize);

      if (!update_result) {
        Logger::udr_db().error("Failed to update SmfRegistration document.");
        return false;
      }
    } else {
      auto insert_result = coll.insert_one(document_value.view());

      if (!insert_result) {
        Logger::udr_db().error("Failed to insert SmfRegistration document.");
        return false;
      }
    }

    to_json(json_data, smfRegistration);
    Logger::udr_db().debug("SmfRegistration PUT: %s", json_data.dump().c_str());

    return true;
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while insert smf context in MongoDB: %s", e.what());
    return false;
  }
}
//------------------------------------------------------------------------------
bool mongo_db::delete_smf_context(
    const std::string& ue_id, const int32_t& pdu_session_id) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["SmfRegistrations"];

  bsoncxx::builder::stream::document query_builder{};
  query_builder << "ueid" << ue_id << "subpduSessionId" << pdu_session_id;

  try {
    auto result = coll.delete_one(query_builder.view());
    if (result->deleted_count() == 0) {
      Logger::udr_db().warn(
          "No documents matching query found. Query: %s",
          bsoncxx::to_json(query_builder.view()).c_str());
      return false;
    }
    Logger::udr_db().debug("SmfRegistration DELETE - successful");
    return true;
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while delete smf context from MongoDB: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool mongo_db::query_smf_registration(
    const std::string& ue_id, const int32_t& pdu_session_id,
    nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["SmfRegistrations"];

  try {
    bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result =
        coll.find_one(
            bsoncxx::builder::stream::document{}
            << "ueid" << ue_id << "subpduSessionId" << pdu_session_id
            << bsoncxx::builder::stream::finalize);

    if (maybe_result) {
      auto doc_view                   = maybe_result->view();
      SmfRegistration smfregistration = {};

      try {
        smfregistration.setSmfInstanceId(
            static_cast<std::string>(doc_view["smfInstanceId"].get_string().value));
        if (doc_view["smfSetId"]) {
          smfregistration.setSmfSetId(
              static_cast<std::string>(doc_view["smfSetId"].get_string().value));
        }
        if (doc_view["supportedFeatures"]) {
          smfregistration.setSupportedFeatures(
              static_cast<std::string>(doc_view["supportedFeatures"].get_string().value));
        }
        smfregistration.setPduSessionId(
            doc_view["pduSessionId"].get_int32().value);
        if (doc_view["singleNssai"]) {
          Snssai singlenssai;
          nlohmann::json::parse(doc_view["singleNssai"].get_string().value)
              .get_to(singlenssai);
          smfregistration.setSingleNssai(singlenssai);
        }

        if (doc_view["dnn"]) {
          smfregistration.setDnn(
              static_cast<std::string>(doc_view["dnn"].get_string().value));
        }
        if (doc_view["emergencyServices"]) {
          if (doc_view["emergencyServices"].get_bool()) {
            smfregistration.setEmergencyServices(true);
          } else {
            smfregistration.setEmergencyServices(false);
          }
        }
        if (doc_view["pcscfRestorationCallbackUri"]) {
          smfregistration.setPcscfRestorationCallbackUri(
              static_cast<std::string>(doc_view["pcscfRestorationCallbackUri"]
                  .get_string()
                  .value));
        }
        if (doc_view["plmnId"]) {
          PlmnId plmnid;
          nlohmann::json::parse(doc_view["plmnId"].get_string().value)
              .get_to(plmnid);
          smfregistration.setPlmnId(plmnid);
        }
        if (doc_view["pgwFqdn"]) {
          smfregistration.setPgwFqdn(
              static_cast<std::string>(doc_view["pgwFqdn"].get_string().value));
        }
        if (doc_view["epdgInd"]) {
          if (doc_view["epdgInd"].get_bool()) {
            smfregistration.setEpdgInd(true);
          } else {
            smfregistration.setEpdgInd(false);
          }
        }
        if (doc_view["deregCallbackUri"]) {
          smfregistration.setDeregCallbackUri(
              static_cast<std::string>(doc_view["deregCallbackUri"].get_string().value));
        }
        if (doc_view["registrationReason"]) {
          RegistrationReason registrationreason;
          nlohmann::json::parse(
              doc_view["registrationReason"].get_string().value)
              .get_to(registrationreason);
          smfregistration.setRegistrationReason(registrationreason);
        }
        if (doc_view["registrationTime"]) {
          smfregistration.setRegistrationTime(
              static_cast<std::string>(doc_view["registrationTime"].get_string().value));
        }
        if (doc_view["contextInfo"]) {
          ContextInfo contextinfo;
          nlohmann::json::parse(doc_view["contextInfo"].get_string().value)
              .get_to(contextinfo);
          smfregistration.setContextInfo(contextinfo);
        }
      } catch (std::exception e) {
        Logger::udr_db().error(
            "Cannot set values for SMF Registration: %s", e.what());
        return false;
      }

      nlohmann::json j = {};
      to_json(j, smfregistration);
      json_data = j;

      Logger::udr_db().debug("SmfRegistration GET: %s", j.dump().c_str());
      return true;
    } else {
      Logger::udr_db().error(
          "SmfRegistration no data！ue_id: %s, pdu_session_id: %d",
          ue_id.c_str(), pdu_session_id);
      return false;
    }
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while query smf context from MongoDB: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool mongo_db::query_smf_reg_list(
    const std::string& ue_id, nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }

  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["SmfRegistrations"];

  bsoncxx::builder::stream::document filter{};
  filter << "ueid" << ue_id;

  try {
    mongocxx::cursor cursor = coll.find(filter.view());

    nlohmann::json j   = {};
    nlohmann::json tmp = {};

    for (const bsoncxx::document::view& doc : cursor) {
      SmfRegistration smfregistration = {};

      tmp.clear();

      if (doc["smfInstanceId"]) {
        smfregistration.setSmfInstanceId(
            static_cast<std::string>(doc["smfInstanceId"].get_string().value));
      }
      if (doc["smfSetId"]) {
        smfregistration.setSmfSetId(
            static_cast<std::string>(doc["smfSetId"].get_string().value));
      }
      if (doc["supportedFeatures"]) {
        smfregistration.setSupportedFeatures(
            static_cast<std::string>(doc["supportedFeatures"].get_string().value));
      }
      if (doc["pduSessionId"]) {
        smfregistration.setPduSessionId(doc["pduSessionId"].get_int32().value);
      }
      if (doc["singleNssai"]) {
        Snssai singlenssai;
        nlohmann::json::parse(doc["singleNssai"].get_string().value)
            .get_to(singlenssai);
        smfregistration.setSingleNssai(singlenssai);
      }
      if (doc["dnn"]) {
        smfregistration.setDnn(static_cast<std::string>(doc["dnn"].get_string().value));
      }
      if (doc["emergencyServices"]) {
        if (doc["emergencyServices"].get_bool()) {
          smfregistration.setEmergencyServices(true);
        } else {
          smfregistration.setEmergencyServices(false);
        }
        if (doc["pcscfRestorationCallbackUri"]) {
          smfregistration.setPcscfRestorationCallbackUri(
              static_cast<std::string>(doc["pcscfRestorationCallbackUri"]
                  .get_string()
                  .value));
        }
        if (doc["plmnId"]) {
          PlmnId plmnid;
          nlohmann::json::parse(doc["plmnId"].get_string().value)
              .get_to(plmnid);
          smfregistration.setPlmnId(plmnid);
        }
        if (doc["pgwFqdn"]) {
          smfregistration.setPgwFqdn(
              static_cast<std::string>(doc["pgwFqdn"].get_string().value));
        }
        if (doc["epdgInd"]) {
          if (doc["epdgInd"].get_bool()) {
            smfregistration.setEpdgInd(true);
          } else {
            smfregistration.setEpdgInd(false);
          }
        }
        if (doc["deregCallbackUri"]) {
          smfregistration.setDeregCallbackUri(
              static_cast<std::string>(doc["deregCallbackUri"].get_string().value));
        }
        if (doc["registrationReason"]) {
          RegistrationReason registrationreason;
          nlohmann::json::parse(doc["registrationReason"].get_string().value)
              .get_to(registrationreason);
          smfregistration.setRegistrationReason(registrationreason);
        }
        if (doc["registrationTime"]) {
          smfregistration.setRegistrationTime(
              static_cast<std::string>(doc["registrationTime"].get_string().value));
        }
        if (doc["contextInfo"]) {
          ContextInfo contextinfo;
          nlohmann::json::parse(doc["contextInfo"].get_string().value)
              .get_to(contextinfo);
          smfregistration.setContextInfo(contextinfo);
        }

        to_json(tmp, smfregistration);
        j += tmp;
      }
    }
    json_data = j;

    Logger::udr_db().debug("SmfRegistrations GET: %s", j.dump().c_str());
    return true;
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while query smf registration list from MongoDB: %s",
        e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool mongo_db::query_smf_select_data(
    const std::string& ue_id, const std::string& serving_plmn_id,
    nlohmann::json& json_data) {
  // Check the connection with DB first
  if (!get_db_connection_status()) {
    Logger::udr_db().info("The connection to MongoDB is currently inactive");
    return false;
  }
  auto db   = mongo_client[udr_cfg.db_conf.db_name.c_str()];
  auto coll = db["SmfSelectionSubscriptionData"];

  auto query_filter = bsoncxx::builder::stream::document{}
                      << "ueid" << ue_id << "servingPlmnid" << serving_plmn_id
                      << bsoncxx::builder::stream::finalize;

  try {
    auto query_result = coll.find_one(query_filter.view());

    if (!query_result) {
      Logger::udr_db().error(
          "SmfSelectionSubscriptionData no data！Query: %s",
          bsoncxx::to_json(query_filter.view()).c_str());
      return false;
    }

    auto smfselectionsubscriptiondata = SmfSelectionSubscriptionData();
    from_json(
        nlohmann::json::parse(bsoncxx::to_json(query_result.value().view())),
        smfselectionsubscriptiondata);

    to_json(json_data, smfselectionsubscriptiondata);

    Logger::udr_db().debug(
        "SmfSelectionSubscriptionData GET: %s", json_data.dump().c_str());

    return true;
  } catch (const mongocxx::exception& e) {
    Logger::udr_db().error(
        "Exception while query smf selection subscription data from MongoDB: "
        "%s",
        e.what());
    return false;
  }
}