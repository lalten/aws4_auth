#include "Aws4Auth.h"

#include <etl/string_view.h>

#include "Credentials.h"
#include "Sha256.h"

namespace Aws4Auth {

headers_t add_x_amz_headers(headers_t headers, const etl::string_view &date_iso8601,
                            const etl::string_view &payload_hash);

constexpr size_t MAX_CANONICAL_REQUEST_STR_LEN =
    MAX_NUM_HEADERS * (MAX_HEADER_NAME_LEN + MAX_HEADER_VALUE_LEN) + MAX_PAYLOAD_LEN;
etl::string<MAX_CANONICAL_REQUEST_STR_LEN> make_canonical_request_string(
    const etl::string_view &http_method, const etl::string_view &uri, const etl::string_view &query,
    const headers_t &headers, const etl::string_view &signed_headers_string, const etl::string_view &payload_hash);

etl::string<MAX_NUM_HEADERS * MAX_HEADER_NAME_LEN> make_signed_header_string(const headers_t &headers);

constexpr size_t MAX_STRING_TO_SIGN_LEN{16 + 1 + 16 + 1 + 55 + 1 + 64};
etl::string<MAX_STRING_TO_SIGN_LEN> make_string_to_sign(const etl::string_view &date_iso8601,
                                                        const Credentials &credentials,
                                                        const etl::string_view &canonical_request_string);

Header make_authorization_header(const Credentials &credentials, const etl::string_view &date_iso8601,
                                 const etl::string_view &signed_headers_string, const etl::string_view &string_to_sign);

headers_t make_authenticated_request_headers(const Credentials &credentials, const etl::string_view &http_method,
                                             const etl::string_view &uri, const etl::string_view &query,
                                             const headers_t &headers, const etl::string_view &date_iso8601,
                                             const etl::string_view &payload) {
  Sha256::hash_str_t payload_hash = Hash{payload};
  auto modified_headers = add_x_amz_headers(headers, date_iso8601, payload_hash);
  auto signed_headers_string = make_signed_header_string(modified_headers);
  auto crs =
      make_canonical_request_string(http_method, uri, query, modified_headers, signed_headers_string, payload_hash);
  auto sts = make_string_to_sign(date_iso8601, credentials, crs);
  modified_headers.insert(make_authorization_header(credentials, date_iso8601, signed_headers_string, sts));
  return modified_headers;
}

headers_t add_x_amz_headers(headers_t headers, const etl::string_view &date_iso8601,
                            const etl::string_view &payload_hash) {
  headers.insert(Header{etl::make_string("x-amz-content-sha256"), payload_hash, true});
  headers.insert(Header{etl::make_string("x-amz-date"), date_iso8601, true});
  return headers;
}

etl::string<MAX_CANONICAL_REQUEST_STR_LEN> make_canonical_request_string(
    const etl::string_view &http_method, const etl::string_view &uri, const etl::string_view &query,
    const headers_t &headers, const etl::string_view &signed_headers_string, const etl::string_view &payload_hash) {
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

etl::string<MAX_NUM_HEADERS * MAX_HEADER_NAME_LEN> make_signed_header_string(const headers_t &headers) {
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

etl::string<MAX_STRING_TO_SIGN_LEN> make_string_to_sign(const etl::string_view &date_iso8601,
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

Header make_authorization_header(const Credentials &credentials, const etl::string_view &date_iso8601,
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

}  // namespace Aws4Auth
