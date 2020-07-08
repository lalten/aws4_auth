#pragma once

#include <unity.h>

#include <etl/array.h>
#include <etl/cstring.h>

#include "Util.h"

namespace util {

void test_lower() {
  TEST_ASSERT_EQUAL_STRING(
      "hello world!", Util::lower(etl::make_string("Hello World!")).c_str());
}

void test_trim() {
  {
    auto input = etl::make_string("Hello World! ");
    TEST_ASSERT_EQUAL_STRING("Hello World!", etl::string<1024>{Util::trim(input)}.c_str());
  }
  {
    auto input = etl::make_string(" Hello World! ");
    TEST_ASSERT_EQUAL_STRING("Hello World!", etl::string<1024>{Util::trim(input)}.c_str());
  }
  {
    auto input = etl::make_string("   \nHello\nWorld!\t\t \n");
    TEST_ASSERT_EQUAL_STRING("Hello\nWorld!", etl::string<1024>{Util::trim(input)}.c_str());
  }
}

} // namespace util
