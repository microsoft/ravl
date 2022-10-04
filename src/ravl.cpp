// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl/ravl.h"

#include "ravl/attestation.h"
#include "ravl/crypto.h"
#include "ravl/http_client.h"
#include "ravl/sgx.h"
#include "ravl/util.h"

#include <map>
#include <mutex>
#include <ratio>
#include <thread>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ravl
{
  using namespace crypto;

  static AttestationRequestTracker attestation_request_tracker;

  class AttestationRequestTrackerImpl
  {
  public:
    using RequestID = AttestationRequestTracker::RequestID;
    using RequestState = AttestationRequestTracker::RequestState;

    struct Request
    {
      Request(
        AttestationRequestTracker::RequestState state,
        Options options,
        std::shared_ptr<const Attestation> attestation,
        std::shared_ptr<HTTPClient> http_client,
        std::function<void(RequestID)>&& callback) :
        state(state),
        options(options),
        attestation(attestation),
        http_client(http_client),
        callback(callback)
      {}

      Request(const Request& other) = delete;
      AttestationRequestTracker::RequestState state = RequestState::ERROR;
      Options options;
      std::shared_ptr<const Attestation> attestation;
      std::shared_ptr<Claims> claims;
      std::shared_ptr<HTTPClient> http_client;
      std::function<void(RequestID)> callback;
    };

    using Requests = std::map<AttestationRequestTracker::RequestID, Request>;
    using URLResponseMap =
      std::map<AttestationRequestTracker::RequestID, HTTPResponses>;

    mutable std::mutex requests_mtx;
    Requests requests;
    std::shared_ptr<HTTPClient> http_client;
    AttestationRequestTracker::RequestID next_request_id = 0;
    mutable std::mutex responses_mtx;
    URLResponseMap url_responses;

    RequestID submit(
      const Options& options,
      std::shared_ptr<const Attestation> attestation,
      std::shared_ptr<HTTPClient> http_client,
      std::function<void(RequestID)>&& callback)
    {
      RequestID request_id;
      Requests::iterator rit;

      {
        std::lock_guard<std::mutex> guard(responses_mtx);

        request_id = next_request_id++;

        auto [it, ok] = requests.try_emplace(
          request_id,
          RequestState::SUBMITTED,
          options,
          attestation,
          http_client,
          std::move(callback));

        if (!ok)
          throw std::bad_alloc();

        rit = it;
      }

      advance(request_id, rit->second);

      return request_id;
    }

    RequestState state(RequestID id) const
    {
      std::lock_guard<std::mutex> guard(requests_mtx);

      auto rit = requests.find(id);
      if (rit == requests.end())
        return RequestState::ERROR;
      else
        return rit->second.state;
    }

    RequestID advance(RequestID id, Request& req)
    {
      switch (req.state)
      {
        case RequestState::ERROR:
          throw std::runtime_error("verification request failed");
        case RequestState::SUBMITTED:
          req.state = RequestState::WAITING_FOR_ENDORSEMENTS;
          if (!prepare_endorsements(id, req))
          {
            req.state = RequestState::HAVE_ENDORSEMENTS;
            advance(id, req);
          }
          break;
        case RequestState::WAITING_FOR_ENDORSEMENTS:
          req.state = RequestState::HAVE_ENDORSEMENTS;
          break;
        case RequestState::HAVE_ENDORSEMENTS:
          verify(id, req);
          req.state = RequestState::FINISHED;
          if (req.callback)
            req.callback(id);
          break;
        case RequestState::FINISHED:
          break;
        default:
          throw std::runtime_error("unexpected request state");
      }

      return req.state;
    }

    bool finished(RequestID id) const
    {
      return state(id) == RequestState::FINISHED;
    }

    std::shared_ptr<Claims> result(RequestID id) const
    {
      std::lock_guard<std::mutex> guard(requests_mtx);

      auto rit = requests.find(id);
      if (rit == requests.end())
        throw std::runtime_error("no such attestation verification request");
      if (rit->second.state != RequestState::FINISHED)
        throw std::runtime_error(
          "attestation verification request not finished");
      if (!rit->second.claims)
        throw std::runtime_error("claim extraction failed");
      return rit->second.claims;
    }

    void erase(RequestID id)
    {
      std::lock_guard<std::mutex> guard(requests_mtx);

      auto rit = requests.find(id);
      if (rit != requests.end())
        requests.erase(rit);
    }

    AttestationRequestTracker::RequestID advance(RequestID id)
    {
      Requests::iterator rit;

      {
        std::lock_guard<std::mutex> guard(requests_mtx);
        rit = requests.find(id);
        if (rit == requests.end())
          throw std::runtime_error("request not found");
      }

      return advance(id, rit->second);
    }

    bool prepare_endorsements(RequestID id, Request& request)
    {
      if (!request.attestation)
        throw std::runtime_error("no attestation to verify");

      const auto& attestation = *request.attestation;
      const auto& options = request.options;
      auto http_client = request.http_client;

      if (options.verbosity > 0)
      {
        log(fmt::format(
          "* Verifying attestation from {}", to_string(attestation.source)));

        log("- Options", 2);
        if (options.fresh_endorsements)
          log("- Fresh endorsements", 4);
        if (options.fresh_root_ca_certificate)
          log("- Fresh root CA certificate", 4);
        if (options.root_ca_certificate)
          log("- Custom root CA certificate", 4);
        if (
          options.certificate_verification.ignore_time ||
          options.certificate_verification.verification_time)
        {
          log("- Certificate verification", 4);
          if (options.certificate_verification.ignore_time)
            log("- Ignore certificate times", 6);
          if (options.certificate_verification.verification_time)
            log("- Use custom certificate verification time", 6);
        }
      }

      try
      {
        auto url_requests = request.attestation->prepare_endorsements(options);
        if (url_requests)
        {
          auto callback = [this, id](HTTPResponses&& r) {
            {
              std::lock_guard<std::mutex> guard(responses_mtx);
              auto [it, ok] = url_responses.emplace(id, r);
              if (!ok)
                throw std::bad_alloc();
            }
            advance(id);
            advance(id);
          };
          http_client->submit(std::move(*url_requests), callback);
          return true;
        }
      }
      catch (std::exception& ex)
      {
        if (options.verbosity > 0)
          log(fmt::format("  - verification failed: {}", ex.what()));
        throw std::runtime_error(
          fmt::format("attestation verification failed: {}", ex.what()));
      }

      return false;
    }

    void verify(RequestID id, Request& request)
    {
      if (!request.attestation)
        throw std::runtime_error("no attestation to verify");

      auto& attestation = *request.attestation;
      const auto& options = request.options;
      auto http_client = request.http_client;

      std::shared_ptr<Claims> claims;

      try
      {
        std::lock_guard<std::mutex> guard(responses_mtx);
        std::vector<HTTPResponse> responses;

        auto rit = url_responses.find(id);
        if (rit != url_responses.end())
        {
          responses.swap(rit->second);
          url_responses.erase(rit);
        }

        claims = attestation.verify(options, responses);
      }
      catch (std::exception& ex)
      {
        throw std::runtime_error(
          fmt::format("attestation verification failed: {}", ex.what()));
      }

      if (options.verbosity > 0)
        log("  - verification successful");

      request.claims = claims;
    }
  };

  AttestationRequestTracker::AttestationRequestTracker()
  {
    implementation = new AttestationRequestTrackerImpl();
  }

  AttestationRequestTracker::~AttestationRequestTracker()
  {
    delete static_cast<AttestationRequestTrackerImpl*>(implementation);
  }

  AttestationRequestTracker::RequestID AttestationRequestTracker::submit(
    const Options& options,
    std::shared_ptr<const Attestation> attestation,
    std::shared_ptr<HTTPClient> http_client,
    std::function<void(RequestID)>&& callback)
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->submit(options, attestation, http_client, std::move(callback));
  }

  AttestationRequestTracker::RequestState AttestationRequestTracker::state(
    RequestID id) const
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->state(id);
  }

  bool AttestationRequestTracker::finished(RequestID id) const
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->finished(id);
  }

  std::shared_ptr<Claims> AttestationRequestTracker::result(RequestID id) const
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->result(id);
  }

  void AttestationRequestTracker::erase(RequestID id)
  {
    static_cast<AttestationRequestTrackerImpl*>(implementation)->erase(id);
  }

  AttestationRequestTracker::RequestID AttestationRequestTracker::advance(
    RequestID id)
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->advance(id);
  }

  std::shared_ptr<Claims> verify_synchronized(
    std::shared_ptr<const Attestation> attestation,
    const Options& options,
    std::shared_ptr<HTTPClient> http_client)
  {
    if (!http_client)
      http_client = std::make_shared<SynchronousHTTPClient>();

    auto id = attestation_request_tracker.submit(
      options,
      attestation,
      http_client,
      [](AttestationRequestTracker::RequestID id) {
        attestation_request_tracker.advance(id);
      });

    auto state = attestation_request_tracker.state(id);
    while (state != AttestationRequestTracker::FINISHED &&
           state != AttestationRequestTracker::ERROR)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      state = attestation_request_tracker.state(id);
    }

    if (state == AttestationRequestTracker::ERROR)
      throw std::runtime_error("error");

    auto r = attestation_request_tracker.result(id);
    attestation_request_tracker.erase(id);
    return r;
  }

  std::shared_ptr<Claims> verify_synchronous(
    std::shared_ptr<const Attestation> attestation, const Options& options)
  {
    auto http_client = std::make_shared<SynchronousHTTPClient>();
    auto requests = attestation->prepare_endorsements(options);
    std::optional<HTTPResponses> http_responses = std::nullopt;
    if (requests)
      http_client->submit(
        std::move(*requests), [&http_responses](HTTPResponses&& r) {
          http_responses = std::move(r);
        });
    return attestation->verify(options, http_responses);
  }
}
