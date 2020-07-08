#include "Util.h"

#include <etl/string_view.h>

constexpr bool is_whitespace(const char c) {
  return c == ' ' || c == '\t' || c == '\n';
}

etl::string_view Util::trim(const etl::string_view &string) {
  auto trimmed = string;
  while (!trimmed.empty() && ::is_whitespace(trimmed.front())) {
    trimmed.remove_prefix(1);
  }
  while (!trimmed.empty() && ::is_whitespace(trimmed.back())) {
    trimmed.remove_suffix(1);
  }
  return trimmed;
}

etl::string_view
Util::date_iso8601_to_yyyymmdd(const etl::string_view &date_iso8601) {
  return {date_iso8601.begin(), 8};
}
