#pragma once

#include <cstddef>

namespace Aws4Auth {

/**
 * Aws4Auth uses the ETL to avoid dynamic memory allocation. This means this library has to reserve enough memory for
 * the applicaton's worst case scenario (longest headers and payload possible). If the defaults below are not
 * sufficient, you can override them by passing e.g. `-DAWS4AUTH_MAX_PAYLOAD_LEN=10000` during compilation.
 */

#if !defined(AWS4AUTH_MAX_NUM_HEADERS)
#define AWS4AUTH_MAX_NUM_HEADERS 32
#endif
#if !defined(AWS4AUTH_MAX_HEADER_NAME_LEN)
#define AWS4AUTH_MAX_HEADER_NAME_LEN 32
#endif
#if !defined(AWS4AUTH_MAX_HEADER_VALUE_LEN)
#define AWS4AUTH_MAX_HEADER_VALUE_LEN 512
#endif
#if !defined(AWS4AUTH_MAX_PAYLOAD_LEN)
#define AWS4AUTH_MAX_PAYLOAD_LEN 4096
#endif

constexpr size_t MAX_NUM_HEADERS{AWS4AUTH_MAX_NUM_HEADERS};
constexpr size_t MAX_HEADER_NAME_LEN{AWS4AUTH_MAX_HEADER_NAME_LEN};
constexpr size_t MAX_HEADER_VALUE_LEN{AWS4AUTH_MAX_HEADER_VALUE_LEN};
constexpr size_t MAX_PAYLOAD_LEN{AWS4AUTH_MAX_PAYLOAD_LEN};

}  // namespace Aws4Auth
