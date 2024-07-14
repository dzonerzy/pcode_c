cmake_minimum_required(VERSION 3.18...3.22)
project(pcode_c)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.14)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()



if(WIN32)
add_compile_options(-D_WINDOWS=1 -O3 -Wall -Wno-sign-compare -D__TERMINAL__ -DLOCAL_ZLIB=1 -DNO_GZIP=1)
else()
  add_compile_options(-O3 -Wall -Wno-sign-compare -D__TERMINAL__ -DLOCAL_ZLIB=1 -DNO_GZIP=1)
endif()

set(ZLIB
  zlib/adler32.c
  zlib/deflate.c
  zlib/inffast.c
  zlib/inflate.c
  zlib/inftrees.c
  zlib/trees.c
  zlib/zutil.c
  )

set(SLEIGH_COMMON
  sleigh/address.cc
  sleigh/compression.cc
  sleigh/context.cc
  sleigh/float.cc
  sleigh/globalcontext.cc
  sleigh/marshal.cc
  sleigh/opcodes.cc
  sleigh/pcodecompile.cc
  sleigh/pcodeparse.cc
  sleigh/pcoderaw.cc
  sleigh/semantics.cc
  sleigh/slaformat.cc
  sleigh/sleigh.cc
  sleigh/sleighbase.cc
  sleigh/slghpatexpress.cc
  sleigh/slghpattern.cc
  sleigh/slghsymbol.cc
  sleigh/space.cc
  sleigh/translate.cc
  sleigh/xml.cc
  )

set(PCODE_C_WRAPPER
    pcode_native.cc
    pcode_wrapper.cc
    ${ZLIB}
    ${SLEIGH_COMMON}
)

add_executable(sleigh
  sleigh/filemanage.cc
  sleigh/slgh_compile.cc
  sleigh/slghparse.cc
  sleigh/slghscan.cc
  ${SLEIGH_COMMON}
  ${ZLIB}
)

# create static library
# the library should be generated after the .sla files are generated
add_library(pcode STATIC ${PCODE_C_WRAPPER})
add_dependencies(pcode sleigh)

# create main test and link with pcode

add_executable(pcode_test test/main.c)
target_include_directories(pcode_test PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(pcode_test PRIVATE pcode)


# now generate all .sla files
# use the sleigh executable to generate the .sla files
# the .sla files are generated in the same directory as the .ldefs files

# Function to generate .sla files
function(generate_sla_files TARGET)
  add_custom_command(
    TARGET ${TARGET}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Generating .sla files..."
    COMMAND sleigh -a ${CMAKE_SOURCE_DIR}/processors
    COMMENT "Generating .sla files using sleigh"
  )
endfunction()

# Call function to generate .sla files
generate_sla_files(sleigh)

# Ensure the .sla files are generated before building pcode
add_custom_target(generate_sla ALL DEPENDS sleigh)
add_dependencies(pcode generate_sla)