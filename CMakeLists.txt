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

cmake_minimum_required(VERSION 3.15)
project(opsick C)

set(CMAKE_C_STANDARD 11)

option(OPSICK_ENABLE_TESTS "Build OPSICK tests." OFF)

option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)

set(${PROJECT_NAME}_INCLUDE_DIR
        ${CMAKE_CURRENT_LIST_DIR}/include
        )

set(${PROJECT_NAME}_HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/constants.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/strncmpic.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/config.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/murmur3.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/router.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/home.h
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/endpoints/pubkey.h
        )

set(${PROJECT_NAME}_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/config.c
        ${CMAKE_CURRENT_LIST_DIR}/src/murmur3.c
        ${CMAKE_CURRENT_LIST_DIR}/src/router.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/home.c
        ${CMAKE_CURRENT_LIST_DIR}/src/endpoints/pubkey.c
        )

set(${PROJECT_NAME}_ENTRYPOINT
        ${CMAKE_CURRENT_LIST_DIR}/src/main.c
        )

if (NOT TARGET mbedtls)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls mbedtls)
endif ()

if (NOT TARGET facil.io)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/facil.io facil.io)
endif ()

if (NOT TARGET l8w8jwt)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt l8w8jwt)
endif ()

if (NOT TARGET tomlc99)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/tomlc99 tomlc99)
endif ()

file(COPY ${CMAKE_CURRENT_LIST_DIR}/src/index.html DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_LIST_DIR}/src/favicon.ico DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_LIST_DIR}/src/config.toml DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_executable(${PROJECT_NAME}
        ${${PROJECT_NAME}_HEADERS}
        ${${PROJECT_NAME}_SOURCES}
        ${${PROJECT_NAME}_ENTRYPOINT}
        )

target_link_libraries(${PROJECT_NAME}
        PUBLIC facil.io
        PUBLIC mbedtls
        PUBLIC mbedx509
        PUBLIC mbedcrypto
        PUBLIC l8w8jwt
        PUBLIC tomlc99
        )

target_include_directories(${PROJECT_NAME}
        PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR}
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include
        )

if (OPSICK_ENABLE_TESTS)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--wrap=malloc,--wrap=calloc")
    endif ()

    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/cmocka cmocka)

    add_executable(run_tests
            ${CMAKE_CURRENT_LIST_DIR}/tests/tests.c
            ${${PROJECT_NAME}_HEADERS}
            ${${PROJECT_NAME}_SOURCES}
            )

    target_include_directories(run_tests
            PUBLIC ${cmocka_INCLUDE_DIR}
            PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR}
            )

    target_link_libraries(run_tests
            PUBLIC facil.io
            PUBLIC mbedtls
            PUBLIC mbedx509
            PUBLIC mbedcrypto
            PUBLIC cmocka
            )

    if (ENABLE_COVERAGE)
        find_package(codecov)
        add_coverage(${PROJECT_NAME})
        add_coverage(run_tests)
        coverage_evaluate()
    endif ()
endif ()
