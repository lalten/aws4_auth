#pragma once

#include <etl/cstring.h>
#include <etl/set.h>

#include "Config.h"

class string_view;

namespace Aws4Auth {

class Header {
 public:
  Header() = default;
  Header(const etl::string_view &header_name, const etl::string_view &value, bool is_signed = true)
      : header_name_(lower(trim(header_name))), value_(trim(value)), is_signed_(is_signed) {
    ETL_ASSERT(!header_name_.truncated(), ETL_ERROR(etl::exception));
    ETL_ASSERT(!value_.truncated(), ETL_ERROR(etl::exception));
  }

  bool operator<(const Header &other) const { return header_name_ < other.header_name_; }

  etl::string<MAX_HEADER_NAME_LEN> &name() { return header_name_; }
  etl::string<MAX_HEADER_NAME_LEN> name() const { return header_name_; }
  etl::string<MAX_HEADER_VALUE_LEN> &value() { return value_; }
  etl::string<MAX_HEADER_VALUE_LEN> value() const { return value_; }
  bool is_signed() const { return is_signed_; }

 private:
  etl::string<MAX_HEADER_NAME_LEN> lower(const etl::string_view &string);
  etl::string_view trim(const etl::string_view &string);

  etl::string<MAX_HEADER_NAME_LEN> header_name_;
  etl::string<MAX_HEADER_VALUE_LEN> value_;
  bool is_signed_{false};
};
}  // namespace Aws4Auth
