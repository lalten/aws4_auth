#pragma once

#include <etl/array.h>
#include <etl/cstring.h>

class Sha256 {
 public:
  static constexpr size_t NUM_HASH_BYTES{32};
  using hash_t = etl::array<uint8_t, NUM_HASH_BYTES>;
  using hash_str_t = etl::string<2 * NUM_HASH_BYTES>;

  Sha256() = default;
  Sha256(const Sha256 &) = default;
  Sha256(Sha256 &&) = default;

  operator hash_str_t() const;
  operator hash_t() const { return hash; }

 protected:
  hash_t hash;
};

class Hmac : public Sha256 {
 public:
  template <typename I, typename K>
  Hmac(const I &input, const K &key) {
    const uint8_t *key_ptr = reinterpret_cast<const uint8_t *>(key.data());
    size_t key_len = key.size();
    const uint8_t *msg_ptr = reinterpret_cast<const uint8_t *>(input.data());
    size_t msg_len = input.size();
    calculate(key_ptr, key_len, msg_ptr, msg_len);
  }

 private:
  void calculate(const uint8_t *key_ptr, const size_t key_len, const uint8_t *msg_ptr, const size_t msg_len);
};

class Hash : public Sha256 {
 public:
  template <typename I>
  explicit Hash(const I &input) {
    const uint8_t *msg_ptr = reinterpret_cast<const uint8_t *>(input.data());
    size_t msg_len = input.size();
    calculate(msg_ptr, msg_len);
  }

 private:
  void calculate(const uint8_t *msg_ptr, size_t msg_len);
};
