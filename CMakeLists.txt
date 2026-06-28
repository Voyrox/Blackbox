cmake_minimum_required(VERSION 3.16)
project(blackbox CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBARCHIVE REQUIRED libarchive)
pkg_check_modules(LIBCRYPTO REQUIRED libcrypto)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

add_executable(blackbox
    src/main.cpp
    src/package/Create/Create.cpp
    src/package/Sign/Sign.cpp
    src/package/Verify/Verify.cpp
    src/package/Approve/Approve.cpp
    src/package/Version/Version.cpp
    src/package/Time/Time.cpp
    src/crypto/lib.cpp
    src/sbom/lib.cpp
    src/store/lib.cpp
    src/policy/lib.cpp
    src/audit/lib.cpp
)

target_include_directories(blackbox PRIVATE
    src
    ${LIBARCHIVE_INCLUDE_DIRS}
    ${LIBCRYPTO_INCLUDE_DIRS}
    ${SQLITE3_INCLUDE_DIRS}
)

target_link_libraries(blackbox
    ${LIBARCHIVE_LIBRARIES}
    ${LIBCRYPTO_LIBRARIES}
    ${SQLITE3_LIBRARIES}
)

enable_testing()
find_package(GTest CONFIG QUIET)
if (NOT GTest_FOUND)
    find_package(GTest MODULE QUIET)
endif ()
if (NOT GTest_FOUND)
    include(FetchContent)
    set(CMAKE_POLICY_DEFAULT_CMP0135 NEW)
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.15.2)
    FetchContent_MakeAvailable(googletest)
endif ()

add_executable(blackbox_test
    tests/test_version.cpp
    tests/test_crypto.cpp
    tests/test_store.cpp
    tests/test_audit.cpp
    tests/test_policy.cpp
    tests/test_package.cpp
    src/package/Version/Version.cpp
    src/package/Time/Time.cpp
    src/crypto/lib.cpp
    src/sbom/lib.cpp
    src/store/lib.cpp
    src/audit/lib.cpp
    src/policy/lib.cpp
    src/package/Create/Create.cpp
    src/package/Sign/Sign.cpp
    src/package/Verify/Verify.cpp
    src/package/Approve/Approve.cpp
)

target_include_directories(blackbox_test PRIVATE
    src
    ${LIBARCHIVE_INCLUDE_DIRS}
    ${LIBCRYPTO_INCLUDE_DIRS}
    ${SQLITE3_INCLUDE_DIRS}
)

target_link_libraries(blackbox_test
    GTest::gtest
    GTest::gtest_main
    ${LIBARCHIVE_LIBRARIES}
    ${LIBCRYPTO_LIBRARIES}
    ${SQLITE3_LIBRARIES}
)

include(GoogleTest)
gtest_discover_tests(blackbox_test)
