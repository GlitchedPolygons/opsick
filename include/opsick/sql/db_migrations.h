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

#ifndef OPSICK_DB_MIGRATIONS_H
#define OPSICK_DB_MIGRATIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/** @private */
static const char SQL_MIGRATION_0000000[] = "CREATE TABLE "
                                            "schema_version(id boolean PRIMARY KEY DEFAULT TRUE, version bigint NOT NULL, last_mod timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP); "
                                            "-- Create single row constraint (via a trigger) for the schema_version table -----------------------\n"
                                            "INSERT INTO schema_version (version) VALUES (0);\n"
                                            "CREATE TRIGGER single_row_guardian_schema_version "
                                            "BEFORE INSERT ON schema_version "
                                            "WHEN (SELECT COUNT(*) FROM config) >= 1 "
                                            "BEGIN "
                                            "SELECT RAISE(FAIL, 'Only one row allowed inside the schema_version table!'); "
                                            "END; ";

/** @private */
static const char SQL_MIGRATION_0000001[] = "CREATE TABLE "
                                            "users(id bigint PRIMARY KEY AUTOINCREMENT, pw TEXT NOT NULL, iat bigint NOT NULL DEFAULT CURRENT_TIMESTAMP, exp bigint, body TEXT NOT NULL, body_sha512 TEXT NOT NULL, public_key_ed25519 TEXT NOT NULL, public_key_curve448 TEXT NOT NULL);\n"
                                            "-- ------------------------------------------------------------------------ \n"
                                            "-- INCREMENT SCHEMA VERSION NUMBER - ALWAYS DO THIS FOR ALL SQL MIGRATIONS! \n"
                                            "-- ------------------------------------------------------------------------ \n"
                                            "UPDATE schema_version SET version = version + 1 WHERE id = true;";

/**
 * All SQL migrations.
 */
static const char* SQL_MIGRATIONS[] = {
    SQL_MIGRATION_0000000, //
    SQL_MIGRATION_0000001, //
};

/**
 * Gets the currently up-to-date schema version number, which also happens to be the correct index for the #SQL_MIGRATIONS array.
 * @return
 */
static inline size_t get_current_schema_version()
{
    return (sizeof(SQL_MIGRATIONS) / sizeof(char*)) - 1;
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_DB_MIGRATIONS_H
