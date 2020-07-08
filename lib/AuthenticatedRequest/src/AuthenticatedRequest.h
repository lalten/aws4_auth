#pragma once

#include <etl/cstring.h>
#include <etl/string_view.h>

#include "CanonicalRequest.h"
#include "Sha256.h"
#include "Signature.h"
#include "StringToSign.h"
#include "Util.h"

class AuthenticatedRequest {
public:
  template <size_t N>
  static etl::string<N>
  get(const etl::string_view &request, const etl::string_view &payload,
      const etl::string_view &date_iso8601,
      const etl::string_view &aws_region_name,
      const etl::string_view &aws_service_name, Signature &signature) {

    auto request_params = CanonicalRequest::ExtractRequestParams<N>(request);
    CanonicalRequest canonical_request{request_params, payload, true};

    return "";
  }

  // template <size_t N>
  static etl::string<1024>
  make_authorization_header(const Signature &signature,
                            const etl::string_view &date_iso8601,
                            const etl::string_view &aws_region_name,
                            const etl::string_view &aws_service_name,
                            const CanonicalRequest &canonical_request) {
    // signature.set_date(date_iso8601);
    printf("signature key:\n%s\n",
           Sha256::hash_to_string(signature.signing_key_).c_str());
    // printf("canonical_request = %s\n",
    //        canonical_request.canonical_request_string.c_str());
    auto string_to_sign = StringToSign::get(
        date_iso8601, aws_region_name, aws_service_name, canonical_request);
    printf("string to sign:\n%s\n", string_to_sign.c_str());
    auto string_signature = signature.get_string_signature(string_to_sign);
    printf("string_signature_hex_string:\n%s\n",
           Sha256::hash_to_string(string_signature).c_str());
    auto string_signature_hex_string = Sha256::hash_to_string(string_signature);

    auto date_yyyymmdd = Util::date_iso8601_to_yyyymmdd(date_iso8601);

    etl::string<1024> result{"AWS4-HMAC-SHA256 "};
    result += "Credential=";
    Util::append(result, signature.get_access_key());
    result += "/";
    Util::append(result, date_yyyymmdd);
    result += "/";
    Util::append(result, aws_region_name);
    result += "/";
    Util::append(result, aws_service_name);
    result += "/";
    result += "aws4_request";
    result += ", ";
    result += "SignedHeaders=";
    Util::append(result, canonical_request.get_signed_headers_string());
    result += ", ";
    result += "Signature=";
    result += string_signature_hex_string;
    return result;
  }
};
