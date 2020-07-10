#include "Credentials.h"

#include <etl/string_view.h>

#include "Sha256.h"

namespace Aws4Auth {
Sha256::hash_str_t Credentials::sign(const etl::string_view &date_iso8601,
                                     const etl::string_view &string_to_sign) const {
  etl::string<44> secret_key{"AWS4"};
  secret_key.append(secret_access_key_.begin(), secret_access_key_.end());
  etl::string_view date_yyyymmdd{date_iso8601.begin(), 8};
  Sha256::hash_t key_date = Hmac{date_yyyymmdd, secret_key};
  Sha256::hash_t key_region = Hmac{aws_region_, key_date};
  Sha256::hash_t key_service = Hmac{aws_service_, key_region};
  Sha256::hash_t key_signing = Hmac{etl::make_string("aws4_request"), key_service};
  return Hmac{string_to_sign, key_signing};
}
}  // namespace Aws4Auth
