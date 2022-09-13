// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <span>
#include <stdexcept>
#include <vector>

inline std::string vec2str(const std::vector<uint8_t>& vec)
{
  return std::string((char*)vec.data(), vec.size());
}

inline void log(const std::string& msg, bool verbose = false)
{
  // if (verbose)
  std::cout << msg << std::endl;
}

template <typename T>
T get(const std::vector<uint8_t>& data, size_t& pos)
{
  if (pos + sizeof(T) > data.size())
    throw std::runtime_error("not enough data");

  T r = 0;
  for (size_t i = 0; i < sizeof(T); i++)
    r = r << 8 | data.at(pos + i);
  pos += sizeof(T);
  return r;
}

inline std::vector<uint8_t> get_n(
  const std::vector<uint8_t>& data, size_t n, size_t& pos)
{
  if (pos + n > data.size())
    throw std::runtime_error("not enough data");

  std::vector<uint8_t> r(n, 0);
  for (size_t i = 0; i < n; i++)
    r[i] = data.at(pos + i);
  pos += n;

  return r;
}

inline std::vector<uint8_t> from_hex(const std::string& s)
{
  if (s.size() % 2)
    throw std::runtime_error("odd number of hex digits");

  std::vector<uint8_t> r;
  for (size_t i = 0; i < s.size(); i += 2)
  {
    uint8_t t;
    if (sscanf(s.c_str() + i, "%02hhx", &t) != 1)
      return {};
    r.push_back(t);
  }
  return r;
}

template <typename T>
T from_hex_t(const std::string& s, bool little_endian = true)
{
  if (s.size() % 2)
    throw std::runtime_error("odd number of hex digits");

  if (2 * sizeof(T) != s.size())
    throw std::runtime_error("hex string incomplete");

  T r = 0;
  for (size_t i = 0; i < sizeof(T); i++)
  {
    uint8_t t;
    if (sscanf(s.c_str() + 2 * i, "%02hhx", &t) != 1)
      return {};
    if (little_endian)
      r |= ((uint64_t)t) << (8 * i);
    else
      r = (r << 8) | t;
  }
  return r;
}

inline void verify_within(const void* ptr, const std::span<const uint8_t>& vec)
{
  if (!(vec.data() <= ptr && ptr < (vec.data() + vec.size())))
    throw std::runtime_error("invalid pointer");
}

inline void verify_within(
  const std::span<const uint8_t>& span, const std::span<const uint8_t>& vec)
{
  verify_within(span.data(), vec);
  verify_within(span.data() + span.size() - 1, vec);
}

inline std::vector<uint8_t> str2vec(const std::string& s)
{
  return {s.data(), s.data() + s.size()};
}

inline bool is_all_zero(const std::vector<uint8_t>& v)
{
  for (const auto& b : v)
    if (b != 0)
      return false;
  return true;
}

inline std::chrono::system_clock::time_point parse_time_point(
  const std::string& s, const std::string& format)
{
  struct tm stm = {};
  auto sres = strptime(s.c_str(), format.c_str(), &stm);
  if (sres == NULL || *sres != '\0')
    throw std::runtime_error("time point parsing failure");
  auto idr = std::chrono::system_clock::from_time_t(timegm(&stm));
  idr -= std::chrono::seconds(stm.tm_gmtoff);
  return idr;
}
