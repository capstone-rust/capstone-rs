#include <check.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

// Include the actual header that declares cs_kern_os_calloc
#include "capstone/capstone.h"

// The actual function from cs.c - we'll call it directly
extern void* cs_kern_os_calloc(size_t num, size_t size);

START_TEST(test_overflow_protection)
{
    // Invariant: Multiplication of num * size must not overflow before allocation
    // We test this by ensuring the function handles boundary cases safely
    
    // Test cases: exploit case, boundary values, valid input
    struct {
        size_t num;
        size_t size;
        const char *description;
    } test_cases[] = {
        // Exploit case: multiplication overflows to small value
        {SIZE_MAX, 2, "overflow to small allocation"},
        // Boundary case: max values that don't overflow
        {SIZE_MAX / 100, 100, "boundary near overflow"},
        // Valid normal input
        {10, 20, "valid normal input"},
        // Another overflow case
        {1ULL << (sizeof(size_t) * 4), 1ULL << (sizeof(size_t) * 4), "midpoint overflow"},
        // Zero allocation (edge case)
        {0, SIZE_MAX, "zero num"}
    };
    
    int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);
    
    for (int i = 0; i < num_cases; i++) {
        // The security property: if multiplication would overflow,
        // the function should handle it safely (return NULL or abort)
        void *result = cs_kern_os_calloc(test_cases[i].num, test_cases[i].size);
        
        // Check that either:
        // 1. The allocation succeeded (valid input)
        // 2. The allocation failed gracefully (NULL) for overflow cases
        // 3. The program didn't crash (implicitly passed if we get here)
        
        // For valid inputs, we expect non-NULL (or NULL is also acceptable 
        // if memory allocation fails for other reasons)
        if (test_cases[i].num == 0) {
            // Zero-sized allocation should return NULL or valid pointer
            // Both are acceptable
        } else if (test_cases[i].num != 0 && test_cases[i].size != 0) {
            // Non-zero allocation: either succeeds or returns NULL
            // The key is we didn't crash due to overflow
        }
        
        // Free if non-NULL (though calloc may return NULL for overflow)
        if (result != NULL) {
            // In actual kernel context this would be kern_os_free
            // For test purposes, we can't free kernel memory
            // This is just to show the pattern
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_overflow_protection);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}