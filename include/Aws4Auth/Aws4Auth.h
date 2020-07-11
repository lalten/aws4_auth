#pragma once

#include "Credentials.h"
#include "Header.h"
#include "Config.h"

class string_view;

namespace Aws4Auth {

using headers_t = etl::set<Header, MAX_NUM_HEADERS>;

headers_t make_authenticated_request_headers(const Credentials &credentials, const etl::string_view &http_method,
                                             const etl::string_view &uri, const etl::string_view &query,
                                             const headers_t &headers, const etl::string_view &date_iso8601,
                                             const etl::string_view &payload);

}  // namespace Aws4Auth
