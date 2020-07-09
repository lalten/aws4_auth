#pragma Once

#include <etl/array.h>
#include <etl/cstring.h>
#include <etl/format_spec.h>
#include <etl/set.h>
#include <etl/string_view.h>
#include <etl/to_string.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

class Sha256 {
 public:
  static constexpr size_t NUM_HASH_BYTES{32};
  using hash_t = etl::array<uint8_t, NUM_HASH_BYTES>;
  using hash_str_t = etl::string<2 * NUM_HASH_BYTES>;

  Sha256() = delete;
  Sha256(const Sha256 &) = default;
  Sha256(Sha256 &&) = default;

  operator hash_str_t() const {
    const auto format = etl::format_spec{}.hex().upper_case(false).width(2).fill('0');
    hash_str_t hex_string{};
    for (const auto &byte : hash) {
      etl::to_string(byte, hex_string, format, true);
    }
    return hex_string;
  }
  operator hash_t() const { return hash; }

 protected:
  hash_t hash;
};

template <typename I, typename K>
class Hmac : public Sha256 {
 public:
  Hmac(const I &input, const K &key) {
    const uint8_t *key_ptr = reinterpret_cast<const uint8_t *>(key.data());
    size_t key_len = key.size();
    const uint8_t *msg_ptr = reinterpret_cast<const uint8_t *>(input.data());
    size_t msg_len = input.size();
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
};

template <typename I>
class Hash : public Sha256 {
 public:
  explicit Hash(const I &input) {
    const uint8_t *msg_ptr = reinterpret_cast<const uint8_t *>(input.data());
    size_t msg_len = input.size();
    uint8_t *result_ptr = hash.data();
    int err = mbedtls_sha256_ret(msg_ptr, msg_len, result_ptr, false);
    ETL_ASSERT(err == 0, ETL_ERROR(etl::exception));
  }
};
