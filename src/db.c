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

#include "opsick/db.h"
#include "opsick/config.h"

static bool initialized = false;
static uint64_t cached_db_schema_version_nr = 0;
static time_t last_db_schema_version_nr_lookup = 0;

bool opsick_db_init()
{
    if (initialized)
        return true;

    return initialized = true;
}

uint64_t opsick_db_get_schema_version_number()
{
    if (last_db_schema_version_nr_lookup + 3600 > time(NULL))
    {
        last_db_schema_version_nr_lookup = time(NULL);
        return cached_db_schema_version_nr;
    }

    return 0;
}

void opsick_db_free()
{
    if (!initialized)
        return;

    initialized = false;
}