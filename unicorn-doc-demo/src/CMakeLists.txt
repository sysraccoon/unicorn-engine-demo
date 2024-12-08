cmake_minimum_required(VERSION 3.15)

project(unicorn-doc-demo VERSION 0.1.0 LANGUAGES C)
set(C_STANDARD 11)

set(CMAKE_C_FLAGS "-Wall -Wextra -pedantic -g -O3 -march=native")

add_executable(unicorn-doc-demo unicorn_doc_demo.c)
target_link_libraries(unicorn-doc-demo pthread unicorn)

