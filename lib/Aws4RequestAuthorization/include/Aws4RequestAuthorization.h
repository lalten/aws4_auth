#pragma once

#include <etl/cstring.h>
#include <etl/set.h>

class Credentials;
class string_view;

class Aws4RequestAuthorization {
 public:
  static constexpr size_t MAX_NUM_HEADERS{32};
  static constexpr size_t MAX_HEADER_NAME_LEN{32};
  static constexpr size_t MAX_HEADER_VALUE_LEN{512};
  static constexpr size_t MAX_PAYLOAD_LEN{4096};

  class Header {
   public:
    Header() = default;
    Header(const etl::string_view &header_name, const etl::string_view &value, bool is_signed = true)
        : header_name_(lower(trim(header_name))), value_(trim(value)), is_signed_(is_signed) {}

    bool operator<(const Header &other) const { return header_name_ < other.header_name_; }

    etl::string<MAX_HEADER_NAME_LEN> &name() { return header_name_; }
    etl::string<MAX_HEADER_NAME_LEN> name() const { return header_name_; }
    etl::string<MAX_HEADER_VALUE_LEN> &value() { return value_; }
    etl::string<MAX_HEADER_VALUE_LEN> value() const { return value_; }
    bool is_signed() const { return is_signed_; }

   private:
    etl::string<MAX_HEADER_NAME_LEN> header_name_;
    etl::string<MAX_HEADER_VALUE_LEN> value_;
    bool is_signed_{false};
  };
  using headers_t = etl::set<Header, MAX_NUM_HEADERS>;

  static headers_t make_authenticated_request_headers(const Credentials &credentials,
                                                      const etl::string_view &http_method, const etl::string_view &uri,
                                                      const etl::string_view &query, const headers_t &headers,
                                                      const etl::string_view &date_iso8601,
                                                      const etl::string_view &payload);

 private:
  static headers_t add_x_amz_headers(headers_t headers, const etl::string_view &date_iso8601,
                                     const etl::string_view &payload_hash);

  static constexpr size_t MAX_CANONICAL_REQUEST_STR_LEN =
      MAX_NUM_HEADERS * (MAX_HEADER_NAME_LEN + MAX_HEADER_VALUE_LEN) + MAX_PAYLOAD_LEN;
  static etl::string<MAX_CANONICAL_REQUEST_STR_LEN> make_canonical_request_string(
      const etl::string_view &http_method, const etl::string_view &uri, const etl::string_view &query,
      const headers_t &headers, const etl::string_view &signed_headers_string, const etl::string_view &date_iso8601,
      const etl::string_view &payload_hash);

  static etl::string<MAX_NUM_HEADERS * MAX_HEADER_NAME_LEN> make_signed_header_string(const headers_t &headers);

  static constexpr size_t MAX_STRING_TO_SIGN_LEN{16 + 1 + 16 + 1 + 55 + 1 + 64};
  static etl::string<MAX_STRING_TO_SIGN_LEN> make_string_to_sign(const etl::string_view &date_iso8601,
                                                                 const Credentials &credentials,
                                                                 const etl::string_view &canonical_request_string);

  static Header make_authorization_header(const Credentials &credentials, const etl::string_view &date_iso8601,
                                          const etl::string_view &signed_headers_string,
                                          const etl::string_view &string_to_sign);

  static etl::string<MAX_HEADER_NAME_LEN> lower(const etl::string_view &string);
  static etl::string_view trim(const etl::string_view &string);
};
