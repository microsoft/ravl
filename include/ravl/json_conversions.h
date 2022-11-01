// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "util.h"

#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <span>
#include <vector>

namespace nlohmann
{
  template <size_t SZ>
  struct adl_serializer<std::array<uint8_t, SZ>>
  {
    inline static void to_json(json& j, const std::array<uint8_t, SZ>& x)
    {
      j = ravl::to_hex(std::span(x));
    }

    inline static void from_json(const json& j, std::array<uint8_t, SZ>& x)
    {
      auto tmp = ravl::vec_from_hex(j.get<std::string>());
      std::copy(tmp.begin(), tmp.end(), x.begin());
    }
  };

  template <>
  struct adl_serializer<std::vector<uint8_t>>
  {
    inline static void to_json(json& j, const std::vector<uint8_t>& x)
    {
      j = ravl::to_hex(x);
    }

    inline static void from_json(const json& j, std::vector<uint8_t>& x)
    {
      x = ravl::vec_from_hex(j.get<std::string>());
    }
  };

  template <typename T>
  struct adl_serializer<std::optional<T>>
  {
    inline static void to_json(json& j, const std::optional<T>& x)
    {
      if (x)
        j = *x;
      else
        j = nullptr;
    }

    inline static void from_json(const json& j, std::optional<T>& x)
    {
      if (j == nullptr)
        x = std::nullopt;
      else
        x = j.get<T>();
    }
  };
}