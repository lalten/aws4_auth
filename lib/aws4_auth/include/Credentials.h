#pragma once

#include <etl/cstring.h>

class string_view;

namespace Aws4Auth {

class Credentials {
 public:
  static constexpr size_t MAX_AWS_REGION_NAME_LEN{16};
  static constexpr size_t MAX_AWS_SERVICE_NAME_LEN{16};
  static constexpr size_t AWS_ACCESS_KEY_LEN{20};
  static constexpr size_t AWS_SECRET_KEY_LEN{40};

  Credentials(const etl::string<AWS_ACCESS_KEY_LEN> &access_key_id,
              const etl::string<AWS_SECRET_KEY_LEN> &secret_access_key,
              const etl::string<MAX_AWS_REGION_NAME_LEN> &aws_region,
              const etl::string<MAX_AWS_SERVICE_NAME_LEN> &aws_service)
      : access_key_id_(access_key_id),
        secret_access_key_(secret_access_key),
        aws_region_(aws_region),
        aws_service_(aws_service) {}

  etl::string<64> sign(const etl::string_view &date_iso8601, const etl::string_view &string_to_sign) const;

  etl::string<AWS_ACCESS_KEY_LEN> get_access_key() const { return access_key_id_; }
  etl::string<MAX_AWS_REGION_NAME_LEN> get_region() const { return aws_region_; }
  etl::string<MAX_AWS_SERVICE_NAME_LEN> get_service() const { return aws_service_; }

 private:
  const etl::string<AWS_ACCESS_KEY_LEN> access_key_id_;
  const etl::string<AWS_SECRET_KEY_LEN> secret_access_key_;
  const etl::string<MAX_AWS_REGION_NAME_LEN> aws_region_;
  const etl::string<MAX_AWS_SERVICE_NAME_LEN> aws_service_;
};

}  // namespace Aws4Auth
