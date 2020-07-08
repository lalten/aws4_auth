#pragma once

#include "AuthenticatedRequest.h"

#include "CanonicalRequest.h"
#include "Signature.h"
#include "Util.h"
#include <etl/cstring.h>
#include <etl/string_view.h>
#include <unity.h>

void test_authenticated_request() {
  //   auto request = etl::make_string("GET / HTTP/1.1\n"
  //                                   "Host: example.com\n"
  //                                   "Content-Type: text/html\n"
  //                                   "X-Amz-Date: 20200703T212815Z\n");
  //   auto payload = etl::empty_string{};
  //   etl::string<16> date_iso8601{"20200703T212815Z"};
  //   etl::string<16> aws_region_name{"eu-central-1"};
  //   etl::string<16> aws_service_name{"iam"};
  //   const etl::string<20> access_key_id{"AKIAIOSFODNN7EXAMPLE"};
  //   const etl::string<40> secret_access_key{
  //       "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"};

  //   Signature signature{access_key_id, secret_access_key, aws_region_name,
  //                       aws_service_name, date_iso8601};

  //   auto request_params =
  //       CanonicalRequest::ExtractRequestParams<1024>(etl::string_view{request});
  //   auto canonical_request = CanonicalRequest{request_params, payload,
  //   false}; auto date_yyyymmdd =
  //   Util::date_iso8601_to_yyyymmdd(date_iso8601); auto
  //   authorization_header_string =
  //       AuthenticatedRequest::make_authorization_header<1024>(
  //           signature, date_yyyymmdd, aws_region_name, aws_service_name,
  //           canonical_request);

  //   auto a = etl::make_string("host");
  //   auto b = etl::make_string("host");
  //   TEST_ASSERT(etl::string_view{a} == etl::string_view{b});

  //   // auto authenticated_request = AuthenticatedRequest::get<1024>(
  //   //     request, payload, date_iso8601, aws_region_name, aws_service_name,
  //   //     signature);

  //   TEST_ASSERT_EQUAL_STRING(
  //       "AWS4-HMAC-SHA256 "
  //       "Credential=AKIAIOSFODNN7EXAMPLE/20200703/eu-central-1/iam/aws4_request,
  //       " "SignedHeaders=host;x-amz-date, " "Signature="
  //       "549235368e84a8a41027858ff3a0101c2ffe493153f3352c1cd01a726b9a4f4a",
  //       authorization_header_string.c_str());

  auto request = etl::make_string("GET / HTTP/1.1\n"
                                  "Host: my-precious-bucket.s3.amazonaws.com\n"
                                  "X-Amz-Date: 20150915T124500Z\n");
  auto payload = etl::empty_string{};
  etl::string<16> date_iso8601{"20150915T124500Z"};
  etl::string<16> aws_region_name{"us-east-1"};
  etl::string<16> aws_service_name{"s3"};
  const etl::string<20> access_key_id{"AKIAIOSFODNN7EXAMPLE"};
  const etl::string<40> secret_access_key{
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"};

  auto request_params =
      CanonicalRequest::ExtractRequestParams<1024>(etl::string_view{request});
  auto canonical_request = CanonicalRequest{request_params, payload, true};

  TEST_ASSERT_EQUAL_STRING(
      "GET\n"
      "/\n"
      "\n"
      "host:my-precious-bucket.s3.amazonaws.com\n"
      "x-amz-content-sha256:"
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
      "x-amz-date:20150915T124500Z\n"
      "\n"
      "host;x-amz-content-sha256;x-amz-date\n"
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      canonical_request.canonical_request_string.c_str());

  auto string_to_sign = StringToSign::get(date_iso8601, aws_region_name,
                                          aws_service_name, canonical_request);

  TEST_ASSERT_EQUAL_STRING(
      "AWS4-HMAC-SHA256\n"
      "20150915T124500Z\n"
      "20150915/us-east-1/s3/aws4_request\n"
      "ef7c45cc2b0f100ea5d65024643f5cbaf83e7ba2717108905acd605cfe17bc6b",
      string_to_sign.c_str());

  Signature signature{access_key_id, secret_access_key, aws_region_name,
                      aws_service_name, date_iso8601};

  TEST_ASSERT_EQUAL_STRING(
      "7b0b3063e375aa1e25890e0cae1c674785b8d8709cd2bf11ec670b96587650da",
      Sha256::hash_to_string(signature.signing_key_).c_str());

  //   TEST_ASSERT_EQUAL_STRING(
  //       "???",
  //       Sha256::hash_to_string(signature.get_string_signature(string_to_sign)).c_str());

  auto authorization_header_string =
      AuthenticatedRequest::make_authorization_header(
          signature, date_iso8601, aws_region_name, aws_service_name,
          canonical_request);

  // auto authenticated_request = AuthenticatedRequest::get<1024>(
  //     request, payload, date_iso8601, aws_region_name, aws_service_name,
  //     signature);

  TEST_ASSERT_EQUAL_STRING(
      "AWS4-HMAC-SHA256 "
      "Credential=AKIAIOSFODNN7EXAMPLE/20150915/us-east-1/s3/aws4_request, "
      "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
      "Signature="
      "182072eb53d85c36b2d791a1fa46a12d23454ec1e921b02075c23aee40166d5a",
      authorization_header_string.c_str());
}
