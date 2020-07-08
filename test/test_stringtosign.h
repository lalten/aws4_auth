#pragma once

#include "StringToSign.h"

#include <unity.h>

#include <etl/cstring.h>

void test_stringtosign() {
  {
    const etl::string<16> date_iso8601{"20130524T000000Z"};
    const etl::string<16> aws_region_name{"us-east-1"};
    const etl::string<16> aws_service_name{"s3"};

    const CanonicalRequest canonical_request{};
    auto string_to_sign = StringToSign::get(
        date_iso8601, aws_region_name, aws_service_name, canonical_request);
    TEST_ASSERT_EQUAL(133, string_to_sign.size());
    TEST_ASSERT_EQUAL_STRING_LEN("AWS4-HMAC-SHA256\n20130524T000000Z\n"
                                 "20130524/us-east-1/s3/aws4_request\n",
                                 string_to_sign.c_str(), 69);
  }
  {
    auto request = etl::make_string(
        "GET https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08 "
        "HTTP/1.1\n"
        "Host: iam.amazonaws.com\n"
        "Content-Type: application/x-www-form-urlencoded; charset=utf-8\n"
        "X-Amz-Date: 20150830T123600Z");
    auto payload = etl::empty_string{};
    etl::string<16> date_iso8601{"20150830T123600Z"};
    etl::string<16> aws_region_name{"eu-central-1"};
    etl::string<16> aws_service_name{"iam"};
    const etl::string<20> access_key_id{"AKIAIOSFODNN7EXAMPLE"};
    const etl::string<40> secret_access_key{
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"};
    auto request_params =
        CanonicalRequest::ExtractRequestParams<1024>(etl::string_view{request});
    auto canonical_request = CanonicalRequest{request_params, payload, false};

    auto string_to_sign = StringToSign::get(
        date_iso8601, aws_region_name, aws_service_name, canonical_request);
    TEST_ASSERT_EQUAL(137, string_to_sign.size());
    TEST_ASSERT_EQUAL_STRING(
        "AWS4-HMAC-SHA256\n"
        "20150830T123600Z\n"
        "20150830/eu-central-1/iam/aws4_request\n"
        "367cd1ec7ef1d4a640ed1489e8e0d67613d1aadadb0e50c5575595d990bb6ee1",
        string_to_sign.c_str());
  }
}
