# tests/aes_test_app/CMakeLists.txt
cmake_minimum_required(VERSION 3.20.0)

# Find the Zephyr build system
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(opentitan_aes_test)

# Add your main.c to the application build
target_sources(app PRIVATE src/main.c)