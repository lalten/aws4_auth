// Data based on: https://czak.pl/2015/09/15/s3-rest-api-with-curl.html

// compile only if in correct env/testing situation
#if defined(UNIT_TEST)

#include <unity.h>

#include "Aws4Auth.h"
#include "Credentials.h"

void setUp() {}
void tearDown() {}

void test_credentials() {
  auto access_key_id = etl::make_string("AKIAIOSFODNN7EXAMPLE");
  auto secret_access_key = etl::make_string("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
  auto aws_region = etl::make_string("us-east-1");
  auto aws_service = etl::make_string("s3");
  auto date_iso8601 = etl::make_string("20150915T124500Z");
  Aws4Auth::Credentials credentials{access_key_id, secret_access_key, aws_region, aws_service};
  auto string_to_sign = etl::make_string(
      "AWS4-HMAC-SHA256\n"
      "20150915T124500Z\n"
      "20150915/us-east-1/s3/aws4_request\n"
      "ef7c45cc2b0f100ea5d65024643f5cbaf83e7ba2717108905acd605cfe17bc6b");

  auto signature = credentials.sign(date_iso8601, string_to_sign);

  TEST_ASSERT_EQUAL_STRING(access_key_id.c_str(), credentials.get_access_key().c_str());
  TEST_ASSERT_EQUAL_STRING(aws_region.c_str(), credentials.get_region().c_str());
  TEST_ASSERT_EQUAL_STRING(aws_service.c_str(), credentials.get_service().c_str());
  TEST_ASSERT_EQUAL_STRING("182072eb53d85c36b2d791a1fa46a12d23454ec1e921b02075c23aee40166d5a", signature.c_str());
}

void test_make_authenticated_request_headers() {
  auto access_key_id = etl::make_string("AKIAIOSFODNN7EXAMPLE");
  auto secret_access_key = etl::make_string("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
  auto aws_region = etl::make_string("us-east-1");
  auto aws_service = etl::make_string("s3");
  auto date_iso8601 = etl::make_string("20150915T124500Z");
  Aws4Auth::Credentials credentials{access_key_id, secret_access_key, aws_region, aws_service};
  
  auto http_method = etl::make_string("GET");
  auto uri = etl::make_string("/");
  auto query = etl::string<1>("");
  auto payload = etl::string<1>("");
  Aws4Auth::headers_t input_headers{
      Aws4Auth::Header{etl::make_string("host"), etl::make_string("my-precious-bucket.s3.amazonaws.com")}};

  auto full_headers = Aws4Auth::make_authenticated_request_headers(credentials, http_method, uri, query, input_headers,
                                                                   date_iso8601, payload);

  TEST_ASSERT_EQUAL_size_t(4, full_headers.size());
  auto fh_it = full_headers.begin();
  TEST_ASSERT_EQUAL_STRING("Authorization", fh_it->name().c_str());
  TEST_ASSERT_EQUAL_STRING(
      "AWS4-HMAC-SHA256 "
      "Credential=AKIAIOSFODNN7EXAMPLE/20150915/us-east-1/s3/aws4_request, "
      "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
      "Signature=182072eb53d85c36b2d791a1fa46a12d23454ec1e921b02075c23aee40166d5a",
      fh_it->value().c_str());
  fh_it++;
  TEST_ASSERT_EQUAL_STRING("host", fh_it->name().c_str());
  TEST_ASSERT_EQUAL_STRING("my-precious-bucket.s3.amazonaws.com", fh_it->value().c_str());
  fh_it++;
  TEST_ASSERT_EQUAL_STRING("x-amz-content-sha256", fh_it->name().c_str());
  TEST_ASSERT_EQUAL_STRING("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", fh_it->value().c_str());
  fh_it++;
  TEST_ASSERT_EQUAL_STRING("x-amz-date", fh_it->name().c_str());
  TEST_ASSERT_EQUAL_STRING("20150915T124500Z", fh_it->value().c_str());
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_credentials);
  RUN_TEST(test_make_authenticated_request_headers);

  UNITY_END();
}

#endif
