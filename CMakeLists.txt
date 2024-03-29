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

cmake_minimum_required(VERSION 3.12)
project(opsick C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

option(OPSICK_ENABLE_TESTS "Build OPSICK tests." OFF)

option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)

find_package(PostgreSQL REQUIRED)

set(${PROJECT_NAME}_INCLUDE_DIR
        ${CMAKE_CURRENT_LIST_DIR}/include
        )

set(${PROJECT_NAME}_ARGON2_IMPL ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/ref.c)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
    set(${PROJECT_NAME}_ARGON2_IMPL ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/opt.c)
endif ()

add_compile_definitions("SQLITE_THREADSAFE=1")

set(${PROJECT_NAME}_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/blake2/blake2b.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/argon2.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/core.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/encoding.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/thread.c
        ${${PROJECT_NAME}_ARGON2_IMPL}
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/constants.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/config.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/murmur3.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/keys.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/router.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/db.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/sql/db_migrations.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/sql/users.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/util.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/user.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints.h
        ${CMAKE_CURRENT_LIST_DIR}/src/config.c
        ${CMAKE_CURRENT_LIST_DIR}/src/murmur3.c
        ${CMAKE_CURRENT_LIST_DIR}/src/keys.c
        ${CMAKE_CURRENT_LIST_DIR}/src/router.c
        ${CMAKE_CURRENT_LIST_DIR}/src/db.c
        ${CMAKE_CURRENT_LIST_DIR}/src/util.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints.c
        )

set(${PROJECT_NAME}_ENTRYPOINT
        ${CMAKE_CURRENT_LIST_DIR}/src/main.c
        )

if (NOT TARGET facil.io)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/facil.io facil.io)
endif ()

if (NOT TARGET cecies)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/cecies cecies)
endif ()

if (NOT TARGET TFAC)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/tfac tfac)
endif ()

if (NOT TARGET orlp-ed25519)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/ed25519 ed25519)
endif ()

configure_file(${CMAKE_CURRENT_LIST_DIR}/src/index.html ${CMAKE_CURRENT_BINARY_DIR}/index.html COPYONLY)
configure_file(${CMAKE_CURRENT_LIST_DIR}/src/favicon.ico ${CMAKE_CURRENT_BINARY_DIR}/favicon.ico COPYONLY)

add_executable(${PROJECT_NAME}
        ${${PROJECT_NAME}_SOURCES}
        ${${PROJECT_NAME}_ENTRYPOINT}
        )

target_link_libraries(${PROJECT_NAME}
        PUBLIC facil.io
        PUBLIC cecies
        PUBLIC TFAC
        PUBLIC orlp-ed25519
        )

target_link_libraries(${PROJECT_NAME} PRIVATE PostgreSQL::PostgreSQL)

if (UNIX AND NOT ANDROID)
    target_link_libraries(${PROJECT_NAME} PRIVATE -lpthread -ldl)
endif ()

target_include_directories(${PROJECT_NAME}
        PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR}
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/ed25519/src
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/include
        )
