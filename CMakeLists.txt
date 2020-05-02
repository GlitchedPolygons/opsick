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
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/config.h
        )

set(${PROJECT_NAME}_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/config.c
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
        )

target_include_directories(${PROJECT_NAME}
        PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR}
        )

if (OPSICK_ENABLE_TESTS)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--wrap=malloc,--wrap=calloc")
    endif()

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
endif()
