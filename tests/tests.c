/*
   Copyright 2020 Raphael Beck
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define TEST_OOM defined(__GNUC__) && !defined(__clang__)

/* A test case that does nothing and succeeds. */
static void null_test_success(void** state)
{
    (void)state;
}

#if TEST_OOM
bool fail_malloc = false;
bool fail_calloc = false;

void* __real_malloc(size_t size);
void* __real_calloc(size_t size);

void* __wrap_malloc(size_t size)
{
    return fail_malloc ? NULL : __real_malloc(size);
}

void* __wrap_calloc(size_t size)
{
    return fail_calloc ? NULL : __real_calloc(size);
}
#endif

// --------------------------------------------------------------------------------------------------------------

int main(void)
{
#if TEST_OOM
    printf("\n\nGCC\n\n");
#endif

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}