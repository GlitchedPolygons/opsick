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

#include <stdio.h>
#include "http.h"
#include "opsick/constants.h"
#include "opsick/config.h"
#include "opsick/router.h"

// Read user config, start listening to HTTP requests
// on the user-defined port and start facil.io
int main(void)
{
    opsick_init_router();

    // TODO: read user config and customize port, nr. of threads, etc... (https://facil.io/0.7.x/http)

    http_listen("3000", NULL, .on_request = opsick_on_request, .max_body_size = 1024 * 1024 * 16, .log = 1);
    fio_start(.threads = 4);

    opsick_free_router();
}
