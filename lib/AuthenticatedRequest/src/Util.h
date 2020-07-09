#pragma once

#include <etl/algorithm.h>
#include <etl/array.h>
#include <etl/cstring.h>
#include <etl/string_view.h>
#include <etl/vector.h>

namespace Util {

template <size_t N = 1024>
etl::string<N> lower(const etl::string_view &string) {
  etl::string<N> result{};

  for (auto it = string.cbegin(); it != string.cend(); it++) {
    char c = *it;
    if (c >= 'A' && c <= 'Z') {
      result.push_back(c - 'A' + 'a');
    } else {
      result.push_back(c);
    }
  }
  return result;
}

etl::string_view trim(const etl::string_view &string);

etl::string_view date_iso8601_to_yyyymmdd(const etl::string_view &iso8601);

template <size_t N>
etl::string<N> &append(etl::string<N> &string, const etl::string_view &extra) {
  string.append(extra.begin(), extra.end());
  return string;
}

} // namespace Util

namespace etl {
class empty_string : public string<1> {};
} // namespace etl
