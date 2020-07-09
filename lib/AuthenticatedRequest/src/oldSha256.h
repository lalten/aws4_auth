#pragma once

#include <etl/array.h>
#include <etl/cstring.h>
#include <etl/format_spec.h>
#include <etl/to_string.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

namespace Sha256 {

using hash_t = etl::array<uint8_t, 32>;

template <typename I, typename K> constexpr hash_t hmac(I input, K key) {
  const uint8_t *key_ptr = reinterpret_cast<const uint8_t *>(key.data());
  size_t key_len = key.size();
  const uint8_t *msg_ptr = reinterpret_cast<const uint8_t *>(input.data());
  size_t msg_len = input.size();

  hash_t result{};
  uint8_t *result_ptr = result.data();
  ETL_ASSERT(result_ptr, ETL_ERROR(etl::exception));
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

  return result;
}

template <typename I> static constexpr hash_t hash(I input) {

  hash_t result;
  int err = mbedtls_sha256_ret(reinterpret_cast<const uint8_t *>(input.data()),
                               input.size(), result.data(), false);
  ETL_ASSERT(err == 0, ETL_ERROR(etl::exception));
  return result;
}

static etl::string<64> hash_to_string(const hash_t &bytes) {
  const auto format =
      etl::format_spec{}.hex().upper_case(false).width(2).fill('0');
  etl::string<64> hex_string{};
  for (const auto &byte : bytes) {
    etl::to_string(byte, hex_string, format, true);
  }
  return hex_string;
}
} // namespace Sha256
