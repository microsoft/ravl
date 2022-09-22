// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_url_requests.h"

#include <chrono>
#include <cstring>
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#include <curl/urlapi.h>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ravl
{
  static bool initialized = false;
  static std::mutex mtx;

  static size_t body_write_fun(
    char* ptr, size_t size, size_t nmemb, void* userdata)
  {
    URLResponse* r = static_cast<URLResponse*>(userdata);
    size_t real_size = nmemb * size;
    r->body += std::string(ptr, real_size);
    return real_size;
  }

  static size_t header_write_fun(
    char* buffer, size_t size, size_t nitems, void* userdata)
  {
    URLResponse* r = static_cast<URLResponse*>(userdata);
    size_t real_size = nitems * size;
    std::string h = std::string(buffer, real_size);
    char* colon = std::strchr(buffer, ':');
    if (colon != NULL)
    {
      std::string key(buffer, colon - buffer);
      std::string value(colon + 2, real_size - (colon - buffer) - 1);
      r->headers.emplace(std::make_pair(key, value));
    }
    return real_size;
  }

  static CURL* easy_setup(
    CURL* curl,
    const std::string& url,
    const std::string& body,
    URLResponse& r,
    bool verbose)
  {
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &r);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_write_fun);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &r);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_write_fun);

    if (verbose)
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (!body.empty())
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());

    return curl;
  }

  URLResponse URLRequest::execute(bool verbose)
  {
    if (!initialized)
    {
      curl_global_init(CURL_GLOBAL_ALL);
      atexit(curl_global_cleanup);
      initialized = true;
    }

    CURL* curl = curl_easy_init();

    if (!curl)
      throw std::runtime_error("libcurl initialization failed");

    while (max_attempts > 0)
    {
      easy_setup(curl, url, body, response, verbose);

      CURLcode curl_code = curl_easy_perform(curl);

      if (curl_code != CURLE_OK)
      {
        curl_easy_cleanup(curl);
        throw std::runtime_error(fmt::format("curl error: {}", curl_code));
      }
      else
      {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.code);

        if (response.code == 429)
        {
          long retry_after = 0;
          curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry_after);
          if (verbose)
            printf("HTTP 429; RETRY after %lds\n", retry_after);
          std::this_thread::sleep_for(std::chrono::seconds(retry_after));
          response.body = "";
          response.headers.clear();
          response.code = 0;
          max_attempts--;
        }
        else
        {
          curl_easy_cleanup(curl);
          return response;
        }
      }
    }

    if (curl)
      curl_easy_cleanup(curl);

    throw std::runtime_error("maxmimum number of URL request retries exceeded");
  }

  URLRequest::Handle URLRequest::start(
    bool verbose, std::function<void(URLResponse&&)> callback)
  {
    if (!initialized)
    {
      curl_global_init(CURL_GLOBAL_ALL);
      atexit(curl_global_cleanup);
      initialized = true;
    }

    CURLM* multi = curl_multi_init();
    CURL* easy = curl_easy_init();

    if (!multi || !easy)
      throw std::bad_alloc();

    easy_setup(easy, url, body, response, verbose);

    curl_multi_add_handle(multi, easy);

    int running_handles = 1;
    CURLMcode curl_code = curl_multi_perform(multi, &running_handles);

    if (curl_code != CURLM_OK)
    {
      curl_multi_remove_handle(multi, easy);
      curl_easy_cleanup(easy);
      curl_multi_cleanup(multi);
      throw std::runtime_error("curl_multi_perform unsuccessful");
    }

    handle = multi;

    this->callback = callback;

    t = std::make_shared<std::thread>([this]() {
      while (!is_complete())
        ;
      if (this->callback)
      {
        std::lock_guard<std::mutex> guard(mtx);
        URLResponse r = response;
        this->callback(std::move(r));
      }
    });

    return 0;
  }

  static bool must_retry(CURL* curl, URLResponse& response, bool verbose)
  {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.code);

    if (response.code == 429)
    {
      long retry_after = 0;
      curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry_after);
      if (verbose)
        printf("HTTP 429; RETRY after %lds\n", retry_after);
      std::this_thread::sleep_for(std::chrono::seconds(retry_after));
      response.body = "";
      response.headers.clear();
      response.code = 0;
      return true;
    }
    else
      return false;
  }

  bool URLRequest::is_complete() const
  {
    std::lock_guard<std::mutex> guard(mtx);
    auto multi = static_cast<CURL*>(handle);

    if (!multi)
      return true;

    int still_running = 0, num_active_fds = 0;

    CURLMcode mc = curl_multi_perform(multi, &still_running);

    if (mc != CURLM_OK)
      throw std::runtime_error("curl_multi_perform failed");

    mc = curl_multi_poll(multi, NULL, 0, 100, &num_active_fds);

    if (mc != CURLM_OK)
      throw std::runtime_error("curl_multi_poll failed");

    if (still_running > 0 || num_active_fds > 0)
      return false;

    struct CURLMsg* m;
    do
    {
      int msgq = 0;
      m = curl_multi_info_read(multi, &msgq);
      if (m)
      {
        if (m->msg != CURLMSG_DONE)
          return false;
        else
        {
          CURL* e = m->easy_handle;
          curl_easy_getinfo(e, CURLINFO_RESPONSE_CODE, &response.code);
          curl_multi_remove_handle(multi, e);
          if (must_retry(e, const_cast<URLResponse&>(response), true))
          {
            curl_multi_add_handle(multi, e);
            return false;
          }
          else
            curl_easy_cleanup(e);
        }
      }
    } while (m);

    return true;
  }

  std::optional<URLResponse> URLRequest::collect()
  {
    if (!is_complete())
      return std::nullopt;
    std::lock_guard<std::mutex> guard(mtx);
    auto multi = static_cast<CURL*>(handle);
    if (multi)
      curl_multi_cleanup(multi);
    handle = NULL;
    if (t)
      t->join();
    t = nullptr;
    return response;
  }

  std::vector<uint8_t> URLResponse::url_decode(const std::string& in)
  {
    int outsz = 0;
    char* decoded = curl_easy_unescape(NULL, in.c_str(), in.size(), &outsz);
    if (!decoded)
      throw std::bad_alloc();
    std::vector<uint8_t> r = {decoded, decoded + outsz};
    free(decoded);
    return r;
  }

  std::vector<uint8_t> URLResponse::get_header_data(
    const std::string& name, bool url_decoded) const
  {
    auto hit = headers.find(name);
    if (hit == headers.end())
      throw std::runtime_error("missing response header '" + name + "'");
    if (url_decoded)
      return url_decode(hit->second);
    else
      return {hit->second.data(), hit->second.data() + hit->second.size()};
  }
}
