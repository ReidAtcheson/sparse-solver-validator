cmake_minimum_required(VERSION 3.20)

project(sparse_solver_validator VERSION 0.1.0 LANGUAGES CXX)

add_library(sparse_solver_validator INTERFACE)
add_library(sparse_solver_validator::sparse_solver_validator ALIAS sparse_solver_validator)

target_compile_features(sparse_solver_validator INTERFACE cxx_std_20)
target_include_directories(
  sparse_solver_validator
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

include(CTest)

if(BUILD_TESTING)
  add_executable(sparse_solver_validator_tests tests/sparse_solver_validator_tests.cpp)
  target_link_libraries(
    sparse_solver_validator_tests
    PRIVATE sparse_solver_validator::sparse_solver_validator
  )
  add_test(NAME sparse_solver_validator_tests COMMAND sparse_solver_validator_tests)
endif()
