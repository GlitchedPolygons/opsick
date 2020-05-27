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

#ifndef OPSICK_DB_H
#define OPSICK_DB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "libpq-fe.h"

/**
 * Initializes the db client, connecting to postgres and setting up everything that's needed to query the database.
 * @return Whether connection with the db could be established successfully or not.
 */
bool opsick_db_init();

/**
 * Gets the current DB schema version number (via a SELECT statement). <p>
 * This number is increased with every DB schema migration, and aligned with the
 * number you find in the file name prefix
 * @return
 */
uint64_t opsick_db_get_schema_version_number();

/**
 * Disconnects from the db and frees all the related resources.
 */
void opsick_db_free();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_DB_H
