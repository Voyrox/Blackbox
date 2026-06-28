cmake_minimum_required(VERSION 3.16)
project(airgapctl CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBARCHIVE REQUIRED libarchive)
pkg_check_modules(LIBCRYPTO REQUIRED libcrypto)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

add_executable(airgapctl
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

target_include_directories(airgapctl PRIVATE
    src
    ${LIBARCHIVE_INCLUDE_DIRS}
    ${LIBCRYPTO_INCLUDE_DIRS}
    ${SQLITE3_INCLUDE_DIRS}
)

target_link_libraries(airgapctl
    ${LIBARCHIVE_LIBRARIES}
    ${LIBCRYPTO_LIBRARIES}
    ${SQLITE3_LIBRARIES}
)

find_package(GTest CONFIG REQUIRED)
enable_testing()

add_executable(airgapctl_test
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

target_include_directories(airgapctl_test PRIVATE
    src
    ${LIBARCHIVE_INCLUDE_DIRS}
    ${LIBCRYPTO_INCLUDE_DIRS}
    ${SQLITE3_INCLUDE_DIRS}
)

target_link_libraries(airgapctl_test
    GTest::gtest
    GTest::gtest_main
    ${LIBARCHIVE_LIBRARIES}
    ${LIBCRYPTO_LIBRARIES}
    ${SQLITE3_LIBRARIES}
)

include(GoogleTest)
gtest_discover_tests(airgapctl_test)
