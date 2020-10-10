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

#include <time.h>
#include <stdint.h>

/**
 * @file db.h
 * @author Raphael Beck
 * @brief Opsick DB interaction functions.
 */

/**
 * Initializes the db client, connecting to sqlite and setting up everything that's needed to query the database. This terminates opsick with a status code of <c>-1</c> in case of a failure!
 */
void opsick_db_init();

/**
 * Gets the current DB schema version number (via a SELECT statement). <p>
 * This number is increased with every DB schema migration.
 * @return The current db schema version number.
 */
uint64_t opsick_db_get_schema_version_number();

/**
 * Gets the id of the last active user.
 * @return User ID of the last user who interacted with the server.
 */
uint64_t opsick_db_get_last_used_userid();

/**
 * Gets the last 128B of trafficked ciphertext.
 * @return
 */
void opsick_db_last_128_bytes_of_ciphertext(uint8_t out[128]);

/**
 * When was the last time somebody checked the db schema version number?
 * @return time_t
 */
time_t opsick_db_get_last_db_schema_version_nr_lookup();

/**
 * Gets the ID of the last inserted row (useful during user creation).
 * @return The found ID as an unsigned 64-bit integer.
 */
uint64_t opsick_db_get_last_insert_rowid();

/**
 * Adds a new user to the DB.
 * @param pw The user's password (hashed).
 * @param exp_utc When the user expires (UTC).
 * @param body The user's encrypted data body.
 * @param public_key_ed25519 The user's public Ed25519 key.
 * @param encrypted_private_key_ed25519 The user's encrypted private Ed25519 key.
 * @param public_key_curve448 The user's public Curve448 key.
 * @param encrypted_private_key_curve448 The user's encrypted private Curve448 key.
 * @param out_user_id Where to write the ID of the freshly created user into.
 * @return <c>0</c> on success; error code in case of a failure.
 */
int opsick_db_create_user(const char* pw, time_t exp_utc, const char* body, const char* public_key_ed25519, const char* encrypted_private_key_ed25519, const char* public_key_curve448, const char* encrypted_private_key_curve448, uint64_t* out_user_id);

/**
 * Deletes a user from the DB.
 * @param user_id The user ID.
 * @return <c>0</c> on success; <c>1</c> if the user was not found or deletion from db failed for some other unknown reason.
 */
int opsick_db_delete_user(uint64_t user_id);

/**
 * Retrieves a user's password (Argon2 hash) and TOTP secret (Base32-encoded string) from the db.
 * @param user_id The user ID.
 * @param out_pw Where to write the retrieved password into (this needs to be at least 256 bytes in size).
 * @param out_totps_base32 Where to write the retrieved TOTP secret into (this needs to be exactly 49 bytes big). This will be filled with <c>0x00</c> if the user doesn't have 2FA configured.
 * @return <c>0</c> on success; <c>1</c> if the user was not found or fetch from db failed for some other unknown reason.
 */
int opsick_db_get_user_pw_and_totps(uint64_t user_id, char* out_pw, char* out_totps_base32);

/**
 * Changes a user's password in the db.
 * @param user_id User ID whose password you want to change.
 * @param new_pw The new pw hash.
 * @return <c>0</c> on success; <c>1</c> on failure.
 */
int opsick_db_set_user_pw(uint64_t user_id, const char* new_pw);

/**
 * Changes a user's TOTPS (TOTP secret for 2FA) in the db.
 * @param user_id User ID whose TOTPS you want to change.
 * @param new_pw The new TOTPS (base32 encoded).
 * @return <c>0</c> on success; <c>1</c> on failure.
 */
int opsick_db_set_user_totps(uint64_t user_id, const char* new_totps);

/**
 * Retrieves a user's body from the db.
 * @param user_id User id.
 * @return <c>0</c> on success; <c>1</c> if the user was not found or fetch from db failed.
 */
int opsick_db_get_user_body(uint64_t user_id);

/**
 * Updates a user's body in the db.
 * @param user_id User id.
 * @param body The new body to write into the db.
 * @return <c>0</c> on success; non-zero on failure.
 */
int opsick_db_set_user_body(uint64_t user_id, const char* body);

/**
 * Gets a user's expiration datetime (UTC) from the db.
 * @param user_id User ID whose expiration date you want to query.
 * @param out_exp Where to write the found expiration date into (will be left alone if the user couldn't be found).
 * @return <c>0</c> on success; non-zero on failure (e.g. \p user_id not found).
 */
int opsick_db_get_user_exp(uint64_t user_id, time_t* out_exp);

/**
 * Sets a new expiration datetime (UTC) to a user in the db.
 * @param user_id ID of the user whose expiration date needs to be changed.
 * @param new_exp The new UTC timestamp of when the user account will become read-only.
 * @return <c>0</c> on success; non-zero on failure.
 */
int opsick_db_set_user_exp(uint64_t user_id, time_t new_exp);

/**
 * Gets a user's keys from the DB and writes them into the passed output ``char*`` buffers (these will be left untouched in case of a failure e.g. \p user_id not found)..
 * @param user_id The id of the user whose keys you want to query from the db.
 * @param out_pubkey_ed25519 Where to write the found public ed25519 key into (allocate 256B just to be sure, it will be NUL-terminated so you can use strlen on it without any trouble).
 * @param out_prvkey_ed25519 Where to write the found private ed25519 key into (allocate 256B just to be sure, it will be NUL-terminated so you can use strlen on it without any trouble).
 * @param out_pubkey_curve448 (same as with ed25519 argument)
 * @param out_prvkey_curve448 (same as with ed25519 argument)
 * @return <c>0</c> on success; non-zero on failure.
 */
int opsick_db_get_user_keys(uint64_t user_id, char* out_pubkey_ed25519, char* out_prvkey_ed25519, char* out_pubkey_curve448, char* out_prvkey_curve448);

/**
 * Updated a user's key pairs in the db.
 * @param user_id User id.
 * @param new_pubkey_ed25519 The new ed25519 public key (NUL-terminated C-string).
 * @param new_prvkey_ed25519 The new ed25519 encrypted private key (NUL-terminated C-string).
 * @param new_pubkey_curve448 The new curve448 public key (NUL-terminated C-string).
 * @param new_prvkey_curve448 The new curve448 encrypted private key (NUL-terminated C-string).
 * @return <c>0</c> on success; non-zero on failure.
 */
int opsick_db_set_user_keys(uint64_t user_id, const char* new_pubkey_ed25519, const char* new_prvkey_ed25519, const char* new_pubkey_curve448, const char* new_prvkey_curve448);

/**
 * Disconnects from the db and frees all the related resources.
 */
void opsick_db_free();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_DB_H
