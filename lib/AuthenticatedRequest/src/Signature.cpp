#include "Signature.h"

#include <etl/array_view.h>
#include <etl/cstring.h>

#include "Sha256.h"

Signature::Signature(const etl::string<20> &access_key_id,
                     const etl::string<40> &secret_access_key,
                     const etl::string<128> &aws_region,
                     const etl::string<128> &aws_service,
                     const etl::optional<etl::string<16>> &date_iso8601)
    : access_key_(access_key_id),
      secret_key_(make_secret_key(secret_access_key)), aws_region_(aws_region),
      aws_service_(aws_service) {

  if (date_iso8601) {
    set_date(*date_iso8601);
  }
}

Signature::aws_secret_key_t
Signature::make_secret_key(const etl::string<40> &secret_access_key) {
  etl::array<uint8_t, 44> key_bytes{'A', 'W', 'S', '4'};
  etl::copy(reinterpret_cast<const uint8_t *>(secret_access_key.begin()),
            reinterpret_cast<const uint8_t *>(secret_access_key.end()),
            key_bytes.begin() + 4);
  return key_bytes;
}

void Signature::set_date(const etl::string_view &date_iso8601) {
  if (date_iso8601_ != date_iso8601) {
    date_iso8601_ = etl::string<16>{date_iso8601};
    update_signing_key(Util::date_iso8601_to_yyyymmdd(date_iso8601_));
  }
}

Sha256::hash_t
Signature::get_string_signature(const etl::string_view string_to_sign) const {

  printf("signing key used: %s\n", Sha256::hash_to_string(signing_key_).c_str());
  printf("signing string_to_sign used: %s\n", etl::string<1024>(string_to_sign).c_str());

  auto ss = Sha256::hmac(string_to_sign, signing_key_);
  printf("ss: %s\n", Sha256::hash_to_string(ss).c_str());
  return ss;
}

void Signature::update_signing_key(const etl::string_view &date_yyyymmdd) {
  // https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html

  Sha256::hash_t key_date = Sha256::hmac(date_yyyymmdd, secret_key_);
  // auto key_date_str = Sha256::hash_to_string(key_date);
  Sha256::hash_t key_region = Sha256::hmac(aws_region_, key_date);
  // auto key_region_str = Sha256::hash_to_string(key_region);
  Sha256::hash_t key_service = Sha256::hmac(aws_service_, key_region);
  // auto key_service_str = Sha256::hash_to_string(key_service);
  const auto aws4_request_str = etl::make_string("aws4_request");
  Sha256::hash_t key_signing = Sha256::hmac(aws4_request_str, key_service);
  // auto key_signing_str = Sha256::hash_to_string(key_signing);
  signing_key_ = key_signing;
}
