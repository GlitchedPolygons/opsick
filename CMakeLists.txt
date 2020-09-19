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
option(OQS_USE_OPENSSL "Build liboqs OpenSSL support." OFF)
option(OQS_BUILD_ONLY_LIB "Don't build liboqs tests and example programs." ON)

set(${PROJECT_NAME}_INCLUDE_DIR
        ${CMAKE_CURRENT_LIST_DIR}/include
        )

set(${PROJECT_NAME}_HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/constants.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/strncmpic.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/config.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/guid.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/murmur3.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/keys.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/router.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/db.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/home.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/pubkey.h
        )

set(${PROJECT_NAME}_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/config.c
        ${CMAKE_CURRENT_LIST_DIR}/src/strncmpic.c
        ${CMAKE_CURRENT_LIST_DIR}/src/guid.c
        ${CMAKE_CURRENT_LIST_DIR}/src/murmur3.c
        ${CMAKE_CURRENT_LIST_DIR}/src/keys.c
        ${CMAKE_CURRENT_LIST_DIR}/src/router.c
        ${CMAKE_CURRENT_LIST_DIR}/src/db.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/home.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/pubkey.c
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

if (NOT TARGET qryptext)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/qryptext qryptext)
endif ()

if (NOT TARGET l8w8jwt)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt l8w8jwt)
endif ()

find_package(SQLite3)

if (NOT SQLite3_FOUND)
    message(FATAL_ERROR "
    CMake failed to find SQLite3 on your system!
    Please make sure to install sqlite3 (into default paths) and try again...
    - FreeBSD:
      - sudo pkg install sqlite3
    - Linux:
      - Arch:                sudo pacman -S sqlite uuid-devel
      - Debian/*buntu:       sudo apt-get install sqlite3 libsqlite3-dev uuid-dev
      - CentOS/Fedora/RHEL:  sudo dnf install sqlite-devel sqlite-tcl uuid-devel
    - macOS:
      - brew install sqlite
    ")
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
        PUBLIC qryptext
        PUBLIC l8w8jwt
        PUBLIC tomlc99
        PUBLIC SQLite::SQLite3
        )

if (UNIX AND NOT APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE -luuid -lm)
endif ()

if (UNIX AND NOT ANDROID)
    target_link_libraries(${PROJECT_NAME} PRIVATE -lpthread)
endif ()

target_include_directories(${PROJECT_NAME}
        PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR}
        )

get_target_property(${PROJECT_NAME}_DEPS_TARGETS ${PROJECT_NAME} LINK_LIBRARIES)

if (OPSICK_ENABLE_TESTS)

    add_executable(run_tests
            ${${PROJECT_NAME}_HEADERS}
            ${${PROJECT_NAME}_SOURCES}
            ${CMAKE_CURRENT_LIST_DIR}/tests/tests.c
            )

    target_link_libraries(run_tests
            PUBLIC ${${PROJECT_NAME}_DEPS_TARGETS}
            )

    target_include_directories(run_tests
            PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
            PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/acutest/include
            )

    if (ENABLE_COVERAGE)
        find_package(codecov)
        add_coverage(${PROJECT_NAME})
        add_coverage(run_tests)
        coverage_evaluate()
    endif ()
endif ()
