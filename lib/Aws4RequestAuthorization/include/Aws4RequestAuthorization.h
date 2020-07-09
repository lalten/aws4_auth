#pragma once

#include <etl/array.h>
#include <etl/cstring.h>
#include <etl/format_spec.h>
#include <etl/set.h>
#include <etl/string_view.h>
#include <etl/to_string.h>
#include <etl/utility.h>

#include "Credentials.h"
#include "Sha256.h"

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
                                                      const etl::string_view &payload) {
    Sha256::hash_str_t payload_hash = Hash{payload};
    auto modified_headers = add_x_amz_headers(headers, date_iso8601, payload_hash);
    auto signed_headers_string = make_signed_header_string(modified_headers);
    auto crs = make_canonical_request_string(http_method, uri, query, modified_headers, signed_headers_string,
                                             date_iso8601, payload_hash);
    auto sts = make_string_to_sign(date_iso8601, credentials, crs);
    modified_headers.insert(make_authorization_header(credentials, date_iso8601, signed_headers_string, sts));
    return modified_headers;
  }

 private:
  static headers_t add_x_amz_headers(headers_t headers, const etl::string_view &date_iso8601,
                                     const etl::string_view &payload_hash) {
    headers.insert(Header{etl::make_string("x-amz-content-sha256"), payload_hash, true});
    headers.insert(Header{etl::make_string("x-amz-date"), date_iso8601, true});
    return headers;
  }

  static constexpr size_t MAX_CANONICAL_REQUEST_STR_LEN =
      MAX_NUM_HEADERS * (MAX_HEADER_NAME_LEN + MAX_HEADER_VALUE_LEN) + MAX_PAYLOAD_LEN;
  static etl::string<MAX_CANONICAL_REQUEST_STR_LEN> make_canonical_request_string(
      const etl::string_view &http_method, const etl::string_view &uri, const etl::string_view &query,
      const headers_t &headers, const etl::string_view &signed_headers_string, const etl::string_view &date_iso8601,
      const etl::string_view &payload_hash) {
    etl::string<MAX_CANONICAL_REQUEST_STR_LEN> crs;
    crs.append(http_method.begin(), http_method.end());
    crs.push_back('\n');
    crs.append(uri.begin(), uri.end());
    crs.push_back('\n');
    crs.append(query.begin(), query.end());
    crs.push_back('\n');
    for (const auto &header : headers) {
      crs += header.name();
      crs.push_back(':');
      crs += header.value();
      crs.push_back('\n');
    }
    crs.push_back('\n');
    crs.append(signed_headers_string.begin(), signed_headers_string.end());
    crs.push_back('\n');
    crs.append(payload_hash.begin(), payload_hash.end());
    return crs;
  }

  static etl::string<MAX_NUM_HEADERS * MAX_HEADER_NAME_LEN> make_signed_header_string(const headers_t &headers) {
    etl::string<MAX_NUM_HEADERS * MAX_HEADER_NAME_LEN> shs;
    etl::for_each_if(
        headers.begin(), headers.end(),
        [&](const Header &header) {
          shs += header.name();
          shs.push_back(';');
        },
        [](const Header &header) { return header.is_signed(); });
    shs.pop_back();
    return shs;
  }

  static constexpr size_t MAX_STRING_TO_SIGN_LEN{16 + 1 + 16 + 1 + 55 + 1 + 64};
  static etl::string<MAX_STRING_TO_SIGN_LEN> make_string_to_sign(const etl::string_view &date_iso8601,
                                                                 const Credentials &credentials,
                                                                 const etl::string_view &canonical_request_string) {
    etl::string<MAX_STRING_TO_SIGN_LEN> sts{"AWS4-HMAC-SHA256"};
    sts.push_back('\n');
    sts.append(date_iso8601.begin(), date_iso8601.end());
    sts.push_back('\n');
    sts.append(etl::string<8>{date_iso8601.begin(), 8});
    sts.push_back('/');
    sts += credentials.get_region();
    sts.push_back('/');
    sts += credentials.get_service();
    sts.push_back('/');
    sts += "aws4_request";
    sts.push_back('\n');
    sts += Hash{canonical_request_string};
    return sts;
  }

  static Header make_authorization_header(const Credentials &credentials, const etl::string_view &date_iso8601,
                                          const etl::string_view &signed_headers_string,
                                          const etl::string_view &string_to_sign) {
    Header header{};
    header.name() = "Authorization";
    header.value() = "AWS4-HMAC-SHA256 ";
    header.value() += "Credential=";
    header.value() += credentials.get_access_key();
    header.value().push_back('/');
    header.value().append(etl::string<8>{date_iso8601.begin(), 8});
    header.value().push_back('/');
    header.value() += credentials.get_region();
    header.value().push_back('/');
    header.value() += credentials.get_service();
    header.value().push_back('/');
    header.value() += "aws4_request, ";
    header.value() += "SignedHeaders=";
    header.value().append(signed_headers_string.begin(), signed_headers_string.end());
    header.value() += ", ";
    header.value() += "Signature=";
    header.value() += credentials.sign(date_iso8601, string_to_sign);
    return header;
  }

  template <size_t N = 1024>
  static etl::string<N> lower(const etl::string_view &string) {
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
  static constexpr bool is_whitespace(const char c) { return c == ' ' || c == '\t' || c == '\n'; }
  static etl::string_view trim(const etl::string_view &string) {
    etl::string_view trimmed{string};
    while (!trimmed.empty() && is_whitespace(trimmed.front())) {
      trimmed.remove_prefix(1);
    }
    while (!trimmed.empty() && is_whitespace(trimmed.back())) {
      trimmed.remove_suffix(1);
    }
    return trimmed;
  }
};
