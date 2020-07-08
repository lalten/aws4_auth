// compile only if in correct env/testing situation
// #if defined(UNIT_TEST)

#include <Signature.h>

#include <unity.h>

#include "Util.h"
#include <etl/cstring.h>

namespace signature {

void test_signature() {
  {
    etl::string<16> date_iso8601{"20150915T124500Z"};
    etl::string<16> aws_region_name{"us-east-1"};
    etl::string<16> aws_service_name{"s3"};
    const etl::string<20> access_key_id{"AKIAIOSFODNN7EXAMPLE"};
    const etl::string<40> secret_access_key{
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"};
    Signature sig{access_key_id, secret_access_key, aws_region_name,
                  aws_service_name, date_iso8601};
    TEST_ASSERT_EQUAL_STRING(
        "7b0b3063e375aa1e25890e0cae1c674785b8d8709cd2bf11ec670b96587650da",
        Sha256::hash_to_string(sig.signing_key_).c_str());

    const auto string_to_sign = etl::make_string(
        "AWS4-HMAC-SHA256\n"
        "20150915T124500Z\n"
        "20150915/us-east-1/s3/aws4_request\n"
        "ef7c45cc2b0f100ea5d65024643f5cbaf83e7ba2717108905acd605cfe17bc6b");
    auto string_signature = sig.get_string_signature(string_to_sign);
    TEST_ASSERT_EQUAL_STRING(
        "182072eb53d85c36b2d791a1fa46a12d23454ec1e921b02075c23aee40166d5a",
        Sha256::hash_to_string(string_signature).c_str());
  }
}

} // namespace signature
