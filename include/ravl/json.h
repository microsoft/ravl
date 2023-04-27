// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <array>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <vector>

namespace ravl
{
  // Custom JSON types and serializers to make sure that we get exactly the
  // right conversions without applications accidentally overwriting the default
  // templates.
  template <typename T, typename = void>
  struct ravl_json_serializer
  {
    template <
      typename BasicJsonType,
      typename U = T,
      typename std::enable_if<
        ((std::is_integral<U>::value || std::is_floating_point<U>::value ||
          std::is_enum<U>::value)),
        int>::type = 0>
    static void from_json(const BasicJsonType& j, U& t)
    {
      nlohmann::from_json(j, t);
    }

    template <
      typename BasicJsonType,
      typename U = T,
      typename std::enable_if<
        ((std::is_integral<U>::value || std::is_floating_point<U>::value ||
          std::is_enum<U>::value)),
        int>::type = 0>
    static void to_json(BasicJsonType& j, const U& t)
    {
      nlohmann::to_json(j, t);
    }

    template <typename BasicJsonType, typename U = T>
    static void from_json(const BasicJsonType& j, std::vector<U>& t)
    {
      nlohmann::from_json(j, t);
    }

    template <typename BasicJsonType, typename U = T>
    static void to_json(BasicJsonType& j, const std::vector<U>& t) noexcept
    {
      nlohmann::to_json(j, t);
    }

    template <typename BasicJsonType, typename U = T, size_t SZ>
    static void from_json(const BasicJsonType& j, std::array<U, SZ>& t)
    {
      nlohmann::from_json(j, t);
    }

    template <typename BasicJsonType, typename U = T, size_t SZ>
    static void to_json(BasicJsonType& j, const std::array<U, SZ>& t) noexcept
    {
      nlohmann::to_json(j, t);
    }

    template <typename BasicJsonType, typename U = T>
    static void from_json(const BasicJsonType& j, std::string& t)
    {
      nlohmann::from_json(j, t);
    }

    template <typename BasicJsonType, typename U = T>
    static void to_json(BasicJsonType& j, const std::string& t) noexcept
    {
      nlohmann::to_json(j, t);
    }

    template <typename BasicJsonType, typename U = T, typename V, typename W>
    static void from_json(const BasicJsonType& j, std::map<V, W>& t)
    {
      nlohmann::from_json(j, t);
    }

    template <typename BasicJsonType, typename U = T, typename V, typename W>
    static void to_json(BasicJsonType& j, const std::map<V, W>& t) noexcept
    {
      nlohmann::to_json(j, t);
    }
  };

  using json = nlohmann::basic_json<
    std::map,
    std::vector,
    std::string,
    bool,
    std::int64_t,
    std::uint64_t,
    double,
    std::allocator,
    ravl_json_serializer>;
}

#define RAVL_JSON_DEFINE_TYPE_NON_INTRUSIVE(T, ...) \
  template <> \
  struct ravl_json_serializer<T> \
  { \
    inline static void to_json( \
      ravl::json& nlohmann_json_j, const T& nlohmann_json_t) \
    { \
      NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) \
    } \
    inline static void from_json( \
      const ravl::json& nlohmann_json_j, T& nlohmann_json_t) \
    { \
      NLOHMANN_JSON_EXPAND( \
        NLOHMANN_JSON_PASTE(NLOHMANN_JSON_FROM, __VA_ARGS__)) \
    } \
  };
