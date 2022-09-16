// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_requests.h"

#include <cstring>
#include <curl/curl.h>
#include <new>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace ravl
{
  static bool initialized = false;

  static size_t body_write_fun(
    char* ptr, size_t size, size_t nmemb, void* userdata)
  {
    Response* r = static_cast<Response*>(userdata);
    size_t real_size = nmemb * size;
    r->body += std::string(ptr, real_size);
    return real_size;
  }

  static size_t header_write_fun(
    char* buffer, size_t size, size_t nitems, void* userdata)
  {
    Response* r = static_cast<Response*>(userdata);
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

  Response Request::execute(bool verbose) const
  {
    if (!initialized)
    {
      curl_global_init(CURL_GLOBAL_ALL);
      atexit(curl_global_cleanup);
      initialized = true;
    }

    Response r;

    CURL* curl = curl_easy_init();
    if (!curl)
      throw std::runtime_error("libcurl initialization failed");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &r);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_write_fun);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &r);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_write_fun);

    if (verbose)
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (!body.empty())
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());

    CURLcode curl_code = curl_easy_perform(curl);
    r.code = curl_code;

    curl_easy_cleanup(curl);
    return r;
  }

  std::vector<uint8_t> Response::url_decode(const std::string& in)
  {
    int outsz = 0;
    char* decoded = curl_easy_unescape(NULL, in.c_str(), in.size(), &outsz);
    if (!decoded)
      throw std::bad_alloc();
    std::vector<uint8_t> r = {decoded, decoded + outsz};
    free(decoded);
    return r;
  }

  std::vector<uint8_t> Response::get_header_data(
    const std::string& name, bool url_decoded) const
  {
    auto hit = headers.find(name);
    if (hit == headers.end())
      throw std::runtime_error("missing reponse header '" + name + "'");
    // printf("HEADER: %s\n", hit->second.c_str());
    if (url_decoded)
      return url_decode(hit->second);
    else
      return {hit->second.data(), hit->second.data() + hit->second.size()};
  }
}
