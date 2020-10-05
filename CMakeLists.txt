#  Copyright 2020 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 3.10)
project(opsick C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

option(OPSICK_ENABLE_TESTS "Build OPSICK tests." OFF)

option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)

set(${PROJECT_NAME}_INCLUDE_DIR
        ${CMAKE_CURRENT_LIST_DIR}/include
        )

set(${PROJECT_NAME}_ARGON2_IMPL ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/ref.c)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
    set(${PROJECT_NAME}_ARGON2_IMPL ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/opt.c)
endif ()

set(${PROJECT_NAME}_HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/lib/sqlite3/sqlite3.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/ed25519.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/fe.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/fixedint.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/ge.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/precomp_data.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/sc.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/sha512.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/blake2/blake2b.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/argon2.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/core.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/encoding.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/thread.c
        ${${PROJECT_NAME}_ARGON2_IMPL}
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/constants.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/strncmpic.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/config.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/guid.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/murmur3.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/keys.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/router.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/db.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/sql/db_migrations.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/sql/users.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/util.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/home.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/pubkey.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/prvkey.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/passwd.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/useradd.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/userdel.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/user2fa.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/userext.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/userbody.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/version.h
        )

set(${PROJECT_NAME}_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/lib/sqlite3/sqlite3.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/add_scalar.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/fe.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/ge.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/key_exchange.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/keypair.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/sc.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/seed.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/sha512.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/sign.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src/verify.c
        ${CMAKE_CURRENT_LIST_DIR}/src/config.c
        ${CMAKE_CURRENT_LIST_DIR}/src/strncmpic.c
        ${CMAKE_CURRENT_LIST_DIR}/src/guid.c
        ${CMAKE_CURRENT_LIST_DIR}/src/murmur3.c
        ${CMAKE_CURRENT_LIST_DIR}/src/keys.c
        ${CMAKE_CURRENT_LIST_DIR}/src/router.c
        ${CMAKE_CURRENT_LIST_DIR}/src/db.c
        ${CMAKE_CURRENT_LIST_DIR}/src/util.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/home.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/pubkey.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/prvkey.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/passwd.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/useradd.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/userdel.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/user2fa.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/userext.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/userbody.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/version.c
        )

set(${PROJECT_NAME}_ENTRYPOINT
        ${CMAKE_CURRENT_LIST_DIR}/src/main.c
        )

if (NOT TARGET facil.io)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/facil.io facil.io)
endif ()

if (NOT TARGET tomlc99)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/tomlc99 tomlc99)
endif ()

if (NOT TARGET cecies)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/cecies cecies)
endif ()

if (NOT TARGET TFAC)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/tfac tfac)
endif ()

configure_file(${CMAKE_CURRENT_LIST_DIR}/src/index.html ${CMAKE_CURRENT_BINARY_DIR}/index.html COPYONLY)
configure_file(${CMAKE_CURRENT_LIST_DIR}/src/favicon.ico ${CMAKE_CURRENT_BINARY_DIR}/favicon.ico COPYONLY)
configure_file(${CMAKE_CURRENT_LIST_DIR}/src/config.toml ${CMAKE_CURRENT_BINARY_DIR}/config.toml COPYONLY)

add_executable(${PROJECT_NAME}
        ${${PROJECT_NAME}_HEADERS}
        ${${PROJECT_NAME}_SOURCES}
        ${${PROJECT_NAME}_ENTRYPOINT}
        )

target_link_libraries(${PROJECT_NAME}
        PUBLIC facil.io
        PUBLIC cecies
        PUBLIC tomlc99
        PUBLIC TFAC
        )

if (UNIX AND NOT APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE -luuid -lm)
endif ()

if (UNIX AND NOT ANDROID)
    target_link_libraries(${PROJECT_NAME} PRIVATE -lpthread)
endif ()

target_include_directories(${PROJECT_NAME}
        PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR}
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/sqlite3
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/include
        )
