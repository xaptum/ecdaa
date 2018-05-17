# Copyright 2017 Xaptum, Inc.
# 
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

macro(add_benchmark case_file)
  get_filename_component(case_name ${case_file} NAME_WE)

  add_executable(${case_name} ${case_file} $<TARGET_OBJECTS:ecdaa_utilities>)

  if(BUILD_SHARED_LIBS)
          target_link_libraries(${case_name} PRIVATE
                                ecdaa)
  else()
          target_link_libraries(${case_name} PRIVATE
                                ecdaa_static)
  endif()

  target_include_directories(${case_name}
          PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                  $<BUILD_INTERFACE:${ECDAA_INTERNAL_UTILITIES_INCLUDE_DIR}>
                  ${TOPLEVEL_BINARY_DIR}/libecdaa
  )

  set_target_properties(${case_name} PROPERTIES
          RUNTIME_OUTPUT_DIRECTORY ${CURRENT_BENCHMARKS_BINARY_DIR}
  )
endmacro()

set(CURRENT_BENCHMARKS_BINARY_DIR ${TOPLEVEL_BINARY_DIR}/benchmarksBin/)

set(ECDAA_BENCHMARKS_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/benchmarks_ZZZ.c
)

foreach(template_file ${ECDAA_BENCHMARKS_FILES})
        expand_template(${template_file} ECDAA_BENCHMARKS_SRCS FALSE)
endforeach()

foreach(benchmark ${ECDAA_BENCHMARKS_SRCS})
        add_benchmark(${benchmark})
endforeach()
