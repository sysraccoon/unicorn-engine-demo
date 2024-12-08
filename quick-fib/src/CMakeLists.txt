cmake_minimum_required(VERSION 3.15)

project(quick-fib VERSION 0.1.0 LANGUAGES C)

set(C_STANDARD 11)
set(CMAKE_BUILD_TYPE Release)

set(CMAKE_C_FLAGS "-Wall -Wextra -pedantic -g -O3 -march=native")

add_executable(quick-fib-demo main.c quick_fib.c)
target_link_libraries(quick-fib-demo PUBLIC m)

add_library(quick-fib.dyn SHARED quick_fib.c)
target_link_libraries(quick-fib.dyn PUBLIC m)

add_library(quick-fib.static SHARED quick_fib.c)
target_link_libraries(quick-fib.static PUBLIC m)
target_link_options(quick-fib.static PUBLIC "-static")

install(TARGETS quick-fib-demo quick-fib.dyn quick-fib.static
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)
