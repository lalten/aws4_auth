#pragma once

#include <etl/cstring.h>
#include <etl/string_view.h>

#include "CanonicalRequest.h"
#include "Util.h"

class StringToSign {
public:
  static etl::string<154> get(const etl::string_view &date_iso8601,
                              const etl::string_view &aws_region_name,
                              const etl::string_view &aws_service_name,
                              const CanonicalRequest &canonical_request) {
    etl::string<16 + 1 + 16 + 1 + 55 + 1 + 64> result{"AWS4-HMAC-SHA256"};
    result += "\n";
    result.append(etl::string<16>{date_iso8601});
    result += "\n";
    result += make_scope(date_iso8601, aws_region_name, aws_service_name);
    result += "\n";
    result += Sha256::hash_to_string(canonical_request.get_hash());
    return result;
  }

private:
  static etl::string<55> make_scope(const etl::string_view &date_iso8601,
                                    const etl::string_view &aws_region_name,
                                    const etl::string_view &aws_service_name) {
    etl::string<8 + 1 + 16 + 1 + 16 + 1 + 12> scope{};
    auto date_yyyymmdd = Util::date_iso8601_to_yyyymmdd(date_iso8601);
    scope.append(etl::string<16>{date_yyyymmdd});
    scope += "/";
    scope.append(etl::string<16>{aws_region_name});
    scope += "/";
    scope.append(etl::string<16>{aws_service_name});
    scope += "/";
    scope += "aws4_request";
    return scope;
  }
};
