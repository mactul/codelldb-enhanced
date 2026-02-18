cmake_minimum_required(VERSION 3.10)

# Find libclang C library
find_library(LIBCLANG_LIBRARY NAMES clang libclang PATHS
    /usr/lib
    /usr/local/lib
    /usr/lib/llvm-*/lib
    ${LLVM_LIBRARY_DIRS}
)

if (NOT LIBCLANG_LIBRARY)
    message(FATAL_ERROR "libclang not found")
endif()

message("Found libclang: ${LIBCLANG_LIBRARY}")

# Find clang-c headers
find_path(CLANG_INCLUDE_DIR clang-c/Index.h PATHS
    /usr/include
    /usr/local/include
    /usr/lib/llvm-*/include
    ${LLVM_INCLUDE_DIRS}
)

if (NOT CLANG_INCLUDE_DIR)
    message(FATAL_ERROR "clang-c/Index.h not found")
endif()

message("Found clang headers: ${CLANG_INCLUDE_DIR}")

# Your executable
add_executable(libclang-expr
    main.c
    preprocessor.c
)

# Include clang headers
target_include_directories(libclang-expr PRIVATE ${CLANG_INCLUDE_DIR})

# Link with libclang (the C API)
target_link_libraries(libclang-expr ${LIBCLANG_LIBRARY})

# Install to the bin/ directory in the extension package
install(TARGETS libclang-expr
    RUNTIME DESTINATION libclang-expr
)
