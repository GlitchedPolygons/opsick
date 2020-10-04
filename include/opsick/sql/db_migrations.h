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

/**
 * @file db_migrations.h
 * @author Raphael Beck
 * @brief Opsick DB migration SQL strings.
 */

/*
 * To modify the opsick db schema, just add the SQL migration script as a static const char[] string down here
 * (like the other ones already there) and don't forget to append SQL_INCR_SCHEMA_NR at the end to increase the version number.
 * Then just add the string to the SQL_MIGRATIONS array and you're done! On the next start, opsick will migrate up to the most recent schema!
 */

/** @private */
#define SQL_INCR_SCHEMA_NR \
    "\n" \
    "-- ------------------------------------------------------------------------ \n" \
    "-- INCREMENT SCHEMA VERSION NUMBER - ALWAYS DO THIS FOR ALL SQL MIGRATIONS! \n" \
    "-- ------------------------------------------------------------------------ \n" \
    "UPDATE schema_version SET version = version + 1, last_mod_utc = strftime('%s','now') WHERE id = true;\n";

/** @private */
static const char SQL_MIGRATION_0000000[] = "CREATE TABLE "
                                            "schema_version(id boolean PRIMARY KEY DEFAULT TRUE, version INTEGER NOT NULL, last_mod_utc INTEGER NOT NULL DEFAULT (strftime('%s','now')));\n"
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
                                            "users("
                                            "id INTEGER PRIMARY KEY, "
                                            "pw TEXT NOT NULL, "
                                            "totps TEXT, "
                                            "iat_utc INTEGER NOT NULL DEFAULT (strftime('%s','now')), "
                                            "exp_utc INTEGER, "
                                            "lastmod_utc INTEGER, "
                                            "body TEXT NOT NULL, "
                                            "public_key_ed25519 TEXT NOT NULL, "
                                            "encrypted_private_key_ed25519 TEXT NOT NULL, "
                                            "public_key_curve448 TEXT NOT NULL, "
                                            "encrypted_private_key_curve448 TEXT NOT NULL"
                                            ");\n"
                                            SQL_INCR_SCHEMA_NR

/**
 * All SQL migrations.
 */
static const char* SQL_MIGRATIONS[] = { //
    SQL_MIGRATION_0000000, //
    SQL_MIGRATION_0000001, //
};

/**
 * Gets the currently available amount of SQL migrations (schemas).
 * @return The amount of schemas: subtract 1 from this and you get the index of the latest schema sql migration.
 */
static inline size_t opsick_get_schema_version_count()
{
    return (sizeof(SQL_MIGRATIONS) / sizeof(char*));
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_DB_MIGRATIONS_H
