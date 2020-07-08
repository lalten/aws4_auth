#pragma once

#include "Sha256.h"
#include "Util.h"

#include <etl/algorithm.h>
#include <etl/format_spec.h>
#include <etl/string_view.h>
#include <etl/vector.h>

class CanonicalRequest {
public:
  static constexpr size_t MAX_NUM_HEADERS{1024};
  static constexpr size_t MAX_HEADER_LENGTH{1024};

  struct Header {
    Header(const etl::string_view &header_name, const etl::string_view &value,
           bool to_be_signed = true)
        : header_name_(Util::lower(Util::trim(header_name))),
          value_(Util::trim(value)), to_be_signed_(to_be_signed) {}

    etl::string<MAX_HEADER_LENGTH> header_name_;
    etl::string<MAX_HEADER_LENGTH> value_;
    bool to_be_signed_;

    bool operator<(const Header &other) {
      return header_name_ < other.header_name_;
    }
  };

  template <size_t N = 1024> struct RequestParams {
    etl::string_view http_method;
    etl::string_view uri;
    etl::string_view query;
    etl::string_view http_version;
    etl::vector<Header, N> headers;
  };

  CanonicalRequest() {}

  CanonicalRequest(const RequestParams<1024> &request_params,

                   const etl::string_view request_payload,
                   bool add_xamzcontentsha256 = true) {

    headers_ = etl::vector<Header, MAX_NUM_HEADERS>{request_params.headers};

    auto payload_hash = Sha256::hash_to_string(Sha256::hash(request_payload));
    if (add_xamzcontentsha256) {
      headers_.push_back(
          Header{etl::make_string("x-amz-content-sha256"), payload_hash, true});
    }
    etl::sort(headers_.begin(), headers_.end());

    canonical_request_string.append(request_params.http_method.begin(),
                                    request_params.http_method.end());
    canonical_request_string += "\n";
    canonical_request_string.append(request_params.uri.begin(),
                                    request_params.uri.end());
    canonical_request_string += "\n";
    canonical_request_string.append(request_params.query.begin(),
                                    request_params.query.end());
    canonical_request_string += "\n";
    canonical_request_string += make_canonical_header_string();
    canonical_request_string += "\n";
    auto signed_headers_string_begin = canonical_request_string.end();
    canonical_request_string += make_signed_header_string();
    signed_headers_string_ = etl::string_view{signed_headers_string_begin,
                                              canonical_request_string.end()};
    canonical_request_string += "\n";
    canonical_request_string += payload_hash;
  }

  Sha256::hash_t get_hash() const {
    return Sha256::hash(canonical_request_string);
  }

  etl::string_view get_signed_headers_string() const {
    return signed_headers_string_;
  }

  template <size_t N>
  static RequestParams<N>
  ExtractRequestParams(const etl::string_view &regular_request) {
    RequestParams<N> result;
    auto first_linefeed =
        etl::find(regular_request.begin(), regular_request.end(), '\n');
    auto first_space = etl::find(regular_request.begin(), first_linefeed, ' ');
    result.http_method = etl::string_view{regular_request.begin(), first_space};
    auto first_slash = etl::find(first_space, first_linefeed, '/');
    auto first_questionmark = etl::find(first_slash, first_linefeed, '?');
    bool query_exists = first_questionmark != first_linefeed;
    auto last_space = etl::find(query_exists ? first_questionmark : first_slash,
                                first_linefeed, ' ');
    result.query = etl::string_view{};
    if (query_exists) {
      result.query = etl::string_view{first_questionmark + 1, last_space};
    }
    result.uri = etl::string_view{first_slash, query_exists ? first_questionmark
                                                            : last_space};
    result.http_version = etl::string_view{last_space + 1, first_linefeed};

    result.headers.clear();
    auto current_linefeed = first_linefeed;
    while (current_linefeed < regular_request.end()) {

      auto next_linefeed =
          etl::find(current_linefeed + 1, regular_request.end(), '\n');
      if (next_linefeed >= regular_request.end()) {
        break;
      }

      auto colon = etl::find(current_linefeed + 1, next_linefeed, ':');
      ETL_ASSERT(colon != next_linefeed, ETL_ASSERT(etl::exception));

      etl::string_view name{current_linefeed + 1, colon};
      etl::string_view value{colon + 1, next_linefeed};

      bool sign = Util::lower(name) == etl::make_string("host") ||
                  Util::lower(name) == etl::make_string("x-amz-date");
      result.headers.emplace_back(name, value, sign);

      current_linefeed = next_linefeed;
    }
    return result;
  }

private:
  etl::string<MAX_NUM_HEADERS * MAX_HEADER_LENGTH>
  make_canonical_header_string() const {
    etl::string<MAX_NUM_HEADERS * MAX_HEADER_LENGTH> header_string{};
    for (const auto &header : headers_) {
      header_string += header.header_name_;
      header_string += ":";
      header_string += header.value_;
      header_string += "\n";
    }

    return header_string;
  }
  etl::string<MAX_HEADER_LENGTH> make_signed_header_string() const {
    etl::string<MAX_HEADER_LENGTH> header_string{};
    etl::for_each_if(
        headers_.begin(), headers_.end(),
        [&](const Header &header) {
          header_string += header.header_name_;
          header_string += ";";
        },
        [](const Header &header) { return header.to_be_signed_; });
    header_string.pop_back();
    // header_string += "\n";

    return header_string;
  }

public:
  etl::string<MAX_NUM_HEADERS * MAX_HEADER_LENGTH> canonical_request_string{};
  etl::string_view signed_headers_string_;
  etl::vector<Header, MAX_NUM_HEADERS> headers_;

}; // namespace CanonicalRequest
