cmake_minimum_required( VERSION 3.5 )

project(eosio_evm)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)

add_contract(peos peos
   ${CMAKE_CURRENT_SOURCE_DIR}/src/peos.cpp
)

target_include_directories(peos
   PUBLIC
   ${CMAKE_CURRENT_SOURCE_DIR}/external
   ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_options(peos PUBLIC -stack-size 32000 -use-freeing-malloc  )

set_target_properties(peos
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)