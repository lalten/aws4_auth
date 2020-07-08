#pragma once

#include "Sha256.h"
#include "Util.h"

#include <unity.h>

#include <etl/cstring.h>

void test_hmac() {
  //   TEST_ASSERT_EQUAL_STRING(
  //       "97d15beaba060d0738ec759ea31865178ab8bb781b2d2107644ba881f399d8d6",
  //       Sha256::hash_to_string(
  //           Sha256::hmac(etl::string<6>{"string"}, etl::string<3>{"key"}))
  //           .c_str());
  //   {
  //     // 5590218d1e63a5b79316be0b46d59fcd40f99664afbba478c82fdb02df82049c
  //     Sha256::hash_t key{0x55, 0x90, 0x21, 0x8d, 0x1e, 0x63, 0xa5, 0xb7,
  //                        0x93, 0x16, 0xbe, 0x0b, 0x46, 0xd5, 0x9f, 0xcd,
  //                        0x40, 0xf9, 0x96, 0x64, 0xaf, 0xbb, 0xa4, 0x78,
  //                        0xc8, 0x2f, 0xdb, 0x02, 0xdf, 0x82, 0x04, 0x9c};
  //     TEST_ASSERT_EQUAL_STRING(
  //         "4d03480f0bc10c4f40c989f3ccc50882e0c2350d678262b5870bd643e2bb9e81",
  //         Sha256::hash_to_string(
  //             Sha256::hmac(etl::make_string("Hello World!"), key))
  //             .c_str());
  //   }
  {
    etl::string<128> key{
        "b2ede84547a9e1c73b85e3e3a7e14f66de28e17cb94c3de4c5141858e1b63b2cf6048d"
        "9aa89707947dc9cb61a95630e93247e7cfa9cb5bf92bcda36a5976bb8f"};
    TEST_ASSERT_EQUAL_STRING(
        "51740cabe01de8335383f65aa2324d5c71b800f47edc9257f1fde425c3452292",
        Sha256::hash_to_string(
            Sha256::hmac(
                etl::make_string(
                    R"({"terminal":"T0010101","card":"9001111112000017","amount":"15.80","receipt_no":"2"})"),
                key))
            .c_str());
  }
}

void test_hash() {
  TEST_ASSERT_EQUAL_STRING(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      Sha256::hash_to_string(Sha256::hash(etl::empty_string{})).c_str());
  TEST_ASSERT_EQUAL_STRING(
      "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
      Sha256::hash_to_string(Sha256::hash(etl::string<13>{"Hello World!"}))
          .c_str());
}
