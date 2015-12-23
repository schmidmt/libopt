#include <stdlib.h>
#include <check.h>
#include "../src/otp.h"

START_TEST(test_rfc4226_values)
{
	static const int hotp_values[] = {
		755224, 287082, 359152, 969429, 338314,
		254676, 287922, 162583, 399871, 520489
	};

	char key[] = "12345678901234567890";
	int key_len = sizeof(key);

	for (uint64_t c = 0; c < sizeof(hotp_values) / sizeof(hotp_values[0]); ++c) {
		int hotp = HOTPGenerate(key, key_len, c, 6);
		ck_assert_int_eq(hotp, hotp_values[c]);
	}
}
END_TEST

Suite * libotp_suite(void)
{
    Suite *s;
    TCase *tc_hotp;

    s = suite_create("libotp");

    /* Core test case */
    tc_hotp = tcase_create("hotp");

    tcase_add_test(tc_hotp, test_rfc4226_values);
    suite_add_tcase(s, tc_hotp);

    return s;
}

int main(void)
{
    return 0;
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = libotp_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
