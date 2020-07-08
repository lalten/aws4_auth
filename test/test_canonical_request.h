#pragma once

#include <CanonicalRequest.h>

#include <unity.h>

#include <etl/cstring.h>

void test_canonical_request() {
  {
    auto http_method = etl::make_string("GET");
    auto uri = etl::make_string("/examplebucket/myphoto.jpg");
    auto query =
        etl::make_string("prefix=somePrefix&marker=someMarker&max-keys=20");
    auto http_version = etl::make_string("HTTP/1.1");
    CanonicalRequest::RequestParams<1024> request_params{
        etl::string_view{http_method},
        etl::string_view{uri},
        etl::string_view{query},
        etl::string_view{http_version},
        etl::vector<CanonicalRequest::Header, 1024>{
            CanonicalRequest::Header{etl::make_string("host"),
                                     etl::make_string("s3.amazonaws.com"),
                                     true},
            CanonicalRequest::Header{etl::make_string("Content-Type"),
                                     etl::make_string("text/html"), false},
            CanonicalRequest::Header{etl::make_string("x-amz-date"),
                                     etl::make_string("20130708T220855Z"),
                                     true},
        },
    };

    const CanonicalRequest canonical_request{request_params,
                                             etl::empty_string{}, true};



    TEST_ASSERT_EQUAL_STRING(
        "GET\n"
        "/examplebucket/myphoto.jpg\n"
        "prefix=somePrefix&marker=someMarker&max-keys=20\n"
        "content-type:text/html\n"
        "host:s3.amazonaws.com\n"
        "x-amz-content-sha256:"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "x-amz-date:20130708T220855Z\n"
        "\n"
        "host;x-amz-content-sha256;x-amz-date\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        canonical_request.canonical_request_string.c_str());
    TEST_ASSERT_EQUAL_STRING(
        "66f94f4bd171c069270c844a89f39f71a34d2e2a55f44ef86068401bc1c85fa0",
        Sha256::hash_to_string(canonical_request.get_hash()).c_str());
  }

  //   {
  //     // https://rdrr.io/cran/aws.signature/man/canonical_request.html
  //     CanonicalRequest::RequestParams request_params{};
  //     const CanonicalRequest canonical_request{
  //         etl::make_string("POST"),
  //         etl::make_string("/"),
  //         etl::empty_string{},
  //         {
  //             CanonicalRequest::Header{etl::make_string("Host"),
  //                                      etl::make_string("iam.amazonaws.com"),
  //                                      true},
  //             CanonicalRequest::Header{
  //                 etl::make_string("Content-Type"),
  //                 etl::make_string(
  //                     "application/x-www-form-urlencoded; charset=utf-8"),
  //                 true},
  //             CanonicalRequest::Header{etl::make_string("X-Amz-Date"),
  //                                      etl::make_string("20110909T233600Z"),
  //                                      true},
  //         },
  //         etl::make_string("Action=ListUsers&Version=2010-05-08"),
  //         false,
  //     };

  //     TEST_ASSERT_EQUAL_STRING(
  //         R"(POST
  // /

  // content-type:application/x-www-form-urlencoded; charset=utf-8
  // host:iam.amazonaws.com
  // x-amz-date:20110909T233600Z

  // content-type;host;x-amz-date
  // b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2)",
  //         canonical_request.canonical_request_string.c_str());
  //     TEST_ASSERT_EQUAL_STRING(
  //         "3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2",
  //         Sha256::hash_to_string(canonical_request.get_hash()).c_str());
  //   }
  //   {
  //     //
  //     https://docs.amazonaws.cn/en_us/general/latest/gr/sigv4-create-canonical-request.html
  //     const CanonicalRequest canonical_request{
  //         etl::make_string("GET"),
  //         etl::make_string("/"),
  //         etl::make_string("Action=ListUsers&Version=2010-05-08"),
  //         {
  //             CanonicalRequest::Header{
  //                 etl::make_string("Host"),
  //                 etl::make_string("iam.cn-north-1.amazonaws.com.cn"), true},
  //             CanonicalRequest::Header{
  //                 etl::make_string("Content-Type"),
  //                 etl::make_string(
  //                     "application/x-www-form-urlencoded; charset=utf-8"),
  //                 true},
  //             CanonicalRequest::Header{etl::make_string("X-Amz-Date"),
  //                                      etl::make_string("20150830T123600Z"),
  //                                      true},
  //         },
  //         etl::empty_string{},
  //         false,
  //     };

  //     TEST_ASSERT_EQUAL_STRING(
  //         R"(GET
  // /
  // Action=ListUsers&Version=2010-05-08
  // content-type:application/x-www-form-urlencoded; charset=utf-8
  // host:iam.cn-north-1.amazonaws.com.cn
  // x-amz-date:20150830T123600Z

  // content-type;host;x-amz-date
  // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)",
  //         canonical_request.canonical_request_string.c_str());
  //     TEST_ASSERT_EQUAL_STRING(
  //         "c0f52cbaae2f5c43042257a73d9eafc6d42e3306a4ebab6d9235f391dff4d990",
  //         Sha256::hash_to_string(canonical_request.get_hash()).c_str());
  //   }

  {
    const auto request = etl::make_string(
        "GET /?Action=ListUsers&Version=2010-05-08 HTTP/1.1\n"
        "Host: iam.cn-north-1.amazonaws.cn\n"
        "Content-Type: application/x-www-form-urlencoded; charset=utf-8\n"
        "X-Amz-Date: 20150830T123600Z\n");

    auto request_params =
        CanonicalRequest::ExtractRequestParams<1024>(etl::string_view{request});

    TEST_ASSERT_EQUAL_STRING(
        "GET", etl::string<1024>{request_params.http_method}.c_str());
    TEST_ASSERT_EQUAL_STRING("/",
                             etl::string<1024>{request_params.uri}.c_str());
    TEST_ASSERT_EQUAL_STRING("Action=ListUsers&Version=2010-05-08",
                             etl::string<1024>{request_params.query}.c_str());
    TEST_ASSERT_EQUAL_STRING(
        "HTTP/1.1", etl::string<1024>{request_params.http_version}.c_str());
    TEST_ASSERT_EQUAL(3, request_params.headers.size());
    TEST_ASSERT_EQUAL_STRING("host",
                             request_params.headers[0].header_name_.c_str());
    TEST_ASSERT_EQUAL_STRING("iam.cn-north-1.amazonaws.cn",
                             request_params.headers[0].value_.c_str());
    TEST_ASSERT_EQUAL_STRING("content-type",
                             request_params.headers[1].header_name_.c_str());
    TEST_ASSERT_EQUAL_STRING("application/x-www-form-urlencoded; charset=utf-8",
                             request_params.headers[1].value_.c_str());
    TEST_ASSERT_EQUAL_STRING("x-amz-date",
                             request_params.headers[2].header_name_.c_str());
    TEST_ASSERT_EQUAL_STRING("20150830T123600Z",
                             request_params.headers[2].value_.c_str());
  }
}
