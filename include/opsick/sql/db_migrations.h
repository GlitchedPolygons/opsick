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
static const char SQL_MIGRATION_0000000[] = "CREATE FUNCTION UTC_NOW()  \n"
                                            "RETURNS BIGINT  \n"
                                            "LANGUAGE PLPGSQL  \n"
                                            "AS  \n"
                                            "$$  \n"
                                            "DECLARE  \n"
                                            "  UTC BIGINT;  \n"
                                            "BEGIN  \n"
                                            "  SELECT CAST(EXTRACT(EPOCH FROM NOW() AT TIME ZONE 'UTC') AS BIGINT) INTO UTC;  \n"
                                            "  RETURN UTC;  \n"
                                            "END;  \n"
                                            "$$;  \n"
                                            "  \n"
                                            "CREATE TABLE   \n"
                                            "SETTINGS  \n"
                                            "(  \n"
                                            "  ID TEXT PRIMARY KEY,  \n"
                                            "  VALUE TEXT DEFAULT ''  \n"
                                            ");  \n"
                                            "  \n"
                                            "CREATE TABLE   \n"
                                            "SCHEMA_VERSION  \n"
                                            "(  \n"
                                            "  ID BOOLEAN PRIMARY KEY DEFAULT TRUE,   \n"
                                            "  VERSION BIGINT NOT NULL,   \n"
                                            "  LAST_MOD_UTC BIGINT NOT NULL DEFAULT UTC_NOW()  \n"
                                            ");  \n"
                                            "  \n"
                                            "-- Create a single-row constraint for the schema_version table (via a trigger).  \n"
                                            "  \n"
                                            "INSERT INTO SCHEMA_VERSION (VERSION) VALUES (0);  \n"
                                            "  \n"
                                            "CREATE FUNCTION INCREASE_SCHEMA_VERSION()  \n"
                                            "RETURNS INTEGER  \n"
                                            "LANGUAGE PLPGSQL  \n"
                                            "AS  \n"
                                            "$$  \n"
                                            "BEGIN  \n"
                                            "  UPDATE SCHEMA_VERSION SET VERSION = VERSION + 1, LAST_MOD_UTC = UTC_NOW() WHERE ID = TRUE;  \n"
                                            "  RETURN 0;  \n"
                                            "END;  \n"
                                            "$$;  \n"
                                            "  \n"
                                            "CREATE FUNCTION ENFORCE_SINGLE_ROW_SCHEMA_VERSION()  \n"
                                            "RETURNS TRIGGER   \n"
                                            "LANGUAGE PLPGSQL   \n"
                                            "AS   \n"
                                            "$$  \n"
                                            "BEGIN  \n"
                                            "  IF (SELECT COUNT(*) FROM SETTINGS) >= 1 THEN   \n"
                                            "    RAISE EXCEPTION 'ONLY ONE ROW ALLOWED INSIDE THE SCHEMA_VERSION TABLE!';   \n"
                                            "  END IF;  \n"
                                            "  RETURN NEW;  \n"
                                            "END;  \n"
                                            "$$;  \n"
                                            "  \n"
                                            "CREATE TRIGGER SINGLE_ROW_GUARDIAN_SCHEMA_VERSION   \n"
                                            "BEFORE INSERT   \n"
                                            "ON SCHEMA_VERSION   \n"
                                            "FOR EACH ROW EXECUTE PROCEDURE ENFORCE_SINGLE_ROW_SCHEMA_VERSION();  \n"
                                            "  \n"
                                            "CREATE TABLE   \n"
                                            "USERS  \n"
                                            "(  \n"
                                            "  ID BIGSERIAL PRIMARY KEY,   \n"
                                            "  PW TEXT NOT NULL,   \n"
                                            "  TOTPS TEXT DEFAULT NULL,   \n"
                                            "  IAT_UTC BIGINT NOT NULL DEFAULT UTC_NOW(),   \n"
                                            "  EXP_UTC BIGINT,   \n"
                                            "  LASTMOD_UTC BIGINT DEFAULT UTC_NOW(),   \n"
                                            "  BODY TEXT NOT NULL,   \n"
                                            "  BODY_SHA512 TEXT NOT NULL,   \n"
                                            "  PUBLIC_KEY_ED25519 TEXT NOT NULL,   \n"
                                            "  ENCRYPTED_PRIVATE_KEY_ED25519 TEXT NOT NULL,   \n"
                                            "  PUBLIC_KEY_CURVE448 TEXT NOT NULL,   \n"
                                            "  ENCRYPTED_PRIVATE_KEY_CURVE448 TEXT NOT NULL  \n"
                                            ");  \n"
                                            "  \n";

/** @private */
static const char SQL_MIGRATION_0000001[] = "SELECT INCREASE_SCHEMA_VERSION();  \n"; // INCREMENT SCHEMA VERSION NUMBER - ALWAYS DO THIS FOR ALL SQL MIGRATIONS!

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
