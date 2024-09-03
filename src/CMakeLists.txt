add_executable(main Main.cpp)

include(FetchContent)

FetchContent_Declare(
        tink
        URL https://github.com/tink-crypto/tink-cc/archive/refs/tags/v2.2.0.zip
        URL_HASH SHA256=88e1442182452caa16d0954ceaf73e17b0aa30837ee6c0cc16bf0112313ce753
)

FetchContent_GetProperties(tink)
if(NOT googletest_POPULATED)
    FetchContent_Populate(tink)
    add_subdirectory(${tink_SOURCE_DIR} ${tink_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

target_link_libraries(main PUBLIC tink::static tink::util::istream_input_stream tink::util::ostream_output_stream)
