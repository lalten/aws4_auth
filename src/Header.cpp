#include "Aws4Auth/Header.h"

#include <etl/cstring.h>
#include <etl/string_view.h>

namespace Aws4Auth {

etl::string<Aws4Auth::MAX_HEADER_NAME_LEN> Header::lower(const etl::string_view &string) {
  etl::string<Aws4Auth::MAX_HEADER_NAME_LEN> result{};
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

static constexpr bool is_whitespace(const char c) { return c == ' ' || c == '\t' || c == '\n'; }

etl::string_view Header::trim(const etl::string_view &string) {
  etl::string_view trimmed{string};
  while (!trimmed.empty() && is_whitespace(trimmed.front())) {
    trimmed.remove_prefix(1);
  }
  while (!trimmed.empty() && is_whitespace(trimmed.back())) {
    trimmed.remove_suffix(1);
  }
  return trimmed;
}

}  // namespace Aws4Auth
