#pragma once

#include <etl/array_view.h>
#include <etl/cstring.h>
#include <etl/optional.h>
#include <etl/string_view.h>
#include <etl/to_string.h>

#include "Sha256.h"
#include "Util.h"

class Signature {
public:
  Signature(const etl::string<20> &access_key_id,
            const etl::string<40> &secret_access_key,
            const etl::string<128> &aws_region,
            const etl::string<128> &aws_service,
            const etl::optional<etl::string<16>> &date_iso8601 = {});
  ~Signature() = default;

  void set_date(const etl::string_view &date_iso8601);
  etl::string_view get_date() const { return date_iso8601_; }

  Sha256::hash_t
  get_string_signature(const etl::string_view string_to_sign) const;

  etl::string_view get_access_key() const {
    return etl::string_view{access_key_};
  }

  // etl::string<1024> make_presign_query_string() const {
  //   etl::string<1024> result{"&X-Amz-Algorithm=AWS4-HMAC-SHA256"
  //                            "&X-Amz-Credential="};
  //   result.append(access_key_);
  //   result += "/";
  //   result.append(
  //       etl::string<8>{Util::date_iso8601_to_yyyymmdd(date_iso8601_)});
  //   result += "/";
  //   result.append(aws_region_);
  //   result += "/";
  //   result.append(aws_service_);
  //   result += "/";
  //   result += "aws4_request";
  //   result += "&X-Amz-Date=";
  //   result.append(date_iso8601_);
  //   result += "&X-Amz-Expires=";
  //   result += "86400", // 24h
  //   // result += "900",  // 15min
  //   result += "&X-Amz-SignedHeaders=host";
  //   result += "&X-Amz-Signature=";
  //   result.append(Sha256::hash_to_string(signing_key_));
  //   return result;
  // }

private:
  using aws_secret_key_t = etl::array<uint8_t, 44>;
  static aws_secret_key_t
  make_secret_key(const etl::string<40> &secret_access_key);

  void update_signing_key(const etl::string_view &date_yyyymmdd);

  const etl::string<20> access_key_;
  const aws_secret_key_t secret_key_;
  const etl::string<128> aws_region_;
  const etl::string<128> aws_service_;
  etl::string<16> date_iso8601_{};

public:
  Sha256::hash_t signing_key_;
};
