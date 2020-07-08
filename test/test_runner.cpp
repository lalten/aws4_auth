// compile only if in correct env/testing situation
#if defined(UNIT_TEST)

#include <unity.h>

#include "test_authenticated_request.h"
#include "test_canonical_request.h"
#include "test_sha256.h"
#include "test_signature.h"
#include "test_stringtosign.h"
#include "test_util.h"
int main() {

  UNITY_BEGIN();

  RUN_TEST(util::test_lower);
  RUN_TEST(util::test_trim);

  RUN_TEST(test_hmac);
  RUN_TEST(test_hash);

  RUN_TEST(signature::test_signature);

  RUN_TEST(test_stringtosign);

  RUN_TEST(test_canonical_request);

  RUN_TEST(test_authenticated_request);

  UNITY_END();
}

#endif
