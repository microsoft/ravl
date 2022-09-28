// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl/url_requests.h"

#include <cstring>
#include <emscripten/fetch.h>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>

#define EMSCRIPTEN_FETCH_DONE 4

// Fetch API: https://emscripten.org/docs/api_reference/fetch.html

namespace ravl
{
  namespace
  {
    // From http://www.geekhideout.com/urlcode.shtml

    /* Converts a hex character to its integer value */
    char from_hex(char ch)
    {
      return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
    }

    /* Converts an integer value to its hex character*/
    char to_hex(char code)
    {
      static char hex[] = "0123456789abcdef";
      return hex[code & 15];
    }

    /* Returns a url-decoded version of str */
    /* IMPORTANT: be sure to free() the returned string after use */
    char* url_decode(const char* str, size_t len)
    {
      const char* pstr = str;
      char *buf = (char*)malloc(len + 1), *pbuf = buf;
      while (*pstr)
      {
        if (*pstr == '%')
        {
          if (pstr[1] && pstr[2])
          {
            *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
            pstr += 2;
          }
        }
        else if (*pstr == '+')
        {
          *pbuf++ = ' ';
        }
        else
        {
          *pbuf++ = *pstr;
        }
        pstr++;
      }
      *pbuf = '\0';
      return buf;
    }
  }

  std::vector<uint8_t> URLResponse::url_decode(const std::string& in)
  {
    char* decoded = ravl::url_decode(in.data(), in.size());
    int len = strlen(decoded);
    if (!decoded)
      throw std::bad_alloc();
    std::vector<uint8_t> r = {decoded, decoded + len};
    free(decoded);
    return r;
  }

  std::vector<uint8_t> URLResponse::get_header_data(
    const std::string& name, bool url_decoded) const
  {
    std::string lname = name;
    std::transform(lname.begin(), lname.end(), lname.begin(), ::tolower);
    auto hit = headers.find(lname);
    if (hit == headers.end())
      throw std::runtime_error("missing response header '" + name + "'");
    if (url_decoded)
      return url_decode(hit->second);
    else
      return {hit->second.data(), hit->second.data() + hit->second.size()};
  }

  std::string URLResponse::get_header_string(
    const std::string& name, bool url_decoded) const
  {
    auto t = get_header_data(name, url_decoded);
    return std::string(t.begin(), t.end());
  }

  URLResponse URLRequest::execute(bool verbose)
  {
    throw std::runtime_error("synchronous fetch not supported");
  }

  class FetchTracker : public URLRequestTracker
  {
  public:
    FetchTracker(bool verbose = false) : URLRequestTracker(verbose) {}

    struct UserData
    {
      FetchTracker* tracker = nullptr;
      size_t id = 0;
      size_t i = 0;
    };

    static emscripten_fetch_t* make_fetch(
      const char* method,
      FetchTracker* tracker,
      size_t id,
      size_t i,
      const std::string& url)
    {
      emscripten_fetch_attr_t* attr = new emscripten_fetch_attr_t();
      emscripten_fetch_attr_init(attr);
      strcpy(attr->requestMethod, method);
      attr->attributes = EMSCRIPTEN_FETCH_LOAD_TO_MEMORY;
      // TODO: request headers into attr->requestHeaders
      // TODO: timeout into attr->timeoutMSecs

      attr->userData = new UserData{tracker, id, i};

      attr->onsuccess = [](struct emscripten_fetch_t* fetch) {
        auto ud = static_cast<UserData*>(fetch->userData);
        ud->tracker->complete(ud->id, ud->i, fetch);
        emscripten_fetch_close(fetch);
      };

      attr->onerror = [](emscripten_fetch_t* fetch) {
        printf(
          "Downloading %s failed, HTTP status: %d.\n",
          fetch->url,
          fetch->status);
        auto ud = static_cast<UserData*>(fetch->userData);
        ud->tracker->complete(ud->id, ud->i, fetch);
        emscripten_fetch_close(fetch);
      };

      attr->onprogress = [](emscripten_fetch_t* fetch) {};

      return emscripten_fetch(attr, url.c_str());
    }

    URLRequestSetId submit(
      URLRequests&& rs, std::function<void(URLResponses&&)>&& callback)
    {
      std::lock_guard<std::mutex> guard(mtx);

      URLRequestSetId id = requests.size();
      auto [it, ok] = requests.emplace(id, TrackedRequests{std::move(rs)});
      if (!ok)
        throw std::bad_alloc();

      TrackedRequests& reqs = it->second;

      auto [rsps_it, rsps_ok] =
        responses.emplace(id, URLResponses(reqs.requests.size()));
      if (!rsps_ok)
        throw std::bad_alloc();

      for (size_t i = 0; i < reqs.requests.size(); i++)
      {
        auto& request = reqs.requests.at(i);
        reqs.fetches.push_back(make_fetch("GET", this, id, i, request.url));
      }

      reqs.callback = callback;

      return id;
    }

    static bool must_retry(
      emscripten_fetch_t* fetch, URLResponse& response, bool verbose)
    {
      if (fetch->status == 429)
      {
        auto q = response.get_header_data("Retry-After", false);
        long retry_after = std::atoi((char*)q.data());
        if (verbose)
          printf("HTTP 429; RETRY after %lds\n", retry_after);
        std::this_thread::sleep_for(std::chrono::seconds(retry_after));
        response.body = "";
        response.headers.clear();
        response.status = 0;
        return true;
      }
      else
        return false;
    }

    void complete(size_t id, size_t i, emscripten_fetch_t* fetch)
    {
      std::lock_guard<std::mutex> guard(mtx);

      auto rqit = requests.find(id);
      if (rqit == requests.end())
        return;

      TrackedRequests& treqs = rqit->second;
      auto& reqs = treqs.requests;
      auto& req = reqs.at(i);

      auto rsit = responses.find(id);
      if (rsit == responses.end())
        throw std::runtime_error("response set not found");

      if (rsit->second.size() != rqit->second.requests.size())
        rsit->second.resize(rqit->second.requests.size());

      if (i >= rsit->second.size())
        throw std::runtime_error("request index too large");

      URLResponse& response = rsit->second.at(i);

      if (must_retry(fetch, response, true))
        treqs.fetches[i] = make_fetch("GET", this, id, i, fetch->url);
      else
      {
        response.status = fetch->status;

        size_t headers_len =
          emscripten_fetch_get_response_headers_length(fetch);
        auto hdrs = std::string(headers_len, ' ');
        emscripten_fetch_get_response_headers(
          fetch, hdrs.data(), headers_len + 1);
        char** hdrs_kv = emscripten_fetch_unpack_response_headers(hdrs.data());
        if (hdrs_kv)
          for (size_t j = 0; hdrs_kv[j] != NULL; j += 2)
            response.headers[hdrs_kv[j]] = hdrs_kv[j + 1];
        emscripten_fetch_free_unpacked_response_headers(hdrs_kv);

        // for (const auto& kv : response.headers)
        //   printf("|%s|=|%s|\n", kv.first.c_str(), kv.second.c_str());

        response.body = {fetch->data, static_cast<size_t>(fetch->numBytes)};

        printf(
          "Complete %zu: %u size %zu/%zu (req. %zu)\n",
          i,
          response.status,
          response.headers.size(),
          response.body.size(),
          id);

        treqs.fetches[i] = NULL;
      }

      if (treqs.callback && is_complete_unlocked(id))
      {
        URLResponses rs;
        rs.swap(rsit->second);
        treqs.callback(std::move(rs));
        requests.erase(id);
        responses.erase(id);
      }
    }

    bool is_complete_unlocked(const URLRequestSetId& id) const
    {
      auto rqit = requests.find(id);
      if (rqit == requests.end())
        return false;

      const TrackedRequests& treqs = rqit->second;

      for (const auto& fetch : treqs.fetches)
        if (fetch)
          return false;

      return true;
    }

    bool is_complete(const URLRequestSetId& id) const
    {
      std::lock_guard<std::mutex> guard(mtx);
      return is_complete_unlocked(id);
    }

  protected:
    mutable std::mutex mtx;

    struct TrackedRequests
    {
      URLRequests requests = {};
      std::vector<emscripten_fetch_t*> fetches;
      std::function<void(URLResponses&&)> callback = nullptr;
    };

    typedef std::unordered_map<URLRequestSetId, TrackedRequests> Requests;
    Requests requests;

    std::unordered_map<URLRequestSetId, URLResponses> responses;
  };

  AsynchronousURLRequestTracker::AsynchronousURLRequestTracker(bool verbose)
  {
    implementation = new FetchTracker(verbose);
  }

  AsynchronousURLRequestTracker::~AsynchronousURLRequestTracker()
  {
    delete static_cast<FetchTracker*>(implementation);
  }

  URLRequestSetId AsynchronousURLRequestTracker::submit(
    URLRequests&& rs, std::function<void(URLResponses&&)>&& callback)
  {
    return static_cast<FetchTracker*>(implementation)
      ->submit(std::move(rs), std::move(callback));
  }

  bool AsynchronousURLRequestTracker::is_complete(
    const URLRequestSetId& id) const
  {
    return static_cast<FetchTracker*>(implementation)->is_complete(id);
  }
}
