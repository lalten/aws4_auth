#include "Sha256.h"

#include <etl/basic_format_spec.h>
#include <etl/to_string.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

Sha256::operator hash_str_t() const {
  const auto format = etl::format_spec{}.hex().upper_case(false).width(2).fill('0');
  hash_str_t hex_string{};
  for (const auto &byte : hash) {
    etl::to_string(byte, hex_string, format, true);
  }
  return hex_string;
}

void Hmac::calculate(const uint8_t *key_ptr, const size_t key_len, const uint8_t *msg_ptr, const size_t msg_len) {
  uint8_t *result_ptr = hash.data();
  int err = 0;

  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  mbedtls_md_context_t ctx_;
  mbedtls_md_init(&ctx_);
  err = mbedtls_md_setup(&ctx_, mbedtls_md_info_from_type(md_type), true);
  ETL_ASSERT(err == 0, ETL_ERROR(etl::exception));
  err = mbedtls_md_hmac_starts(&ctx_, key_ptr, key_len);
  ETL_ASSERT(err == 0, ETL_ERROR(etl::exception));
  err = mbedtls_md_hmac_update(&ctx_, msg_ptr, msg_len);
  ETL_ASSERT(err == 0, ETL_ERROR(etl::exception));
  err = mbedtls_md_hmac_finish(&ctx_, result_ptr);
  ETL_ASSERT(err == 0, ETL_ERROR(etl::exception));
  mbedtls_md_free(&ctx_);
}

void Hash::calculate(const uint8_t *msg_ptr, size_t msg_len) {
  uint8_t *result_ptr = hash.data();
  int err = mbedtls_sha256_ret(msg_ptr, msg_len, result_ptr, false);
  ETL_ASSERT(err == 0, ETL_ERROR(etl::exception));
}
