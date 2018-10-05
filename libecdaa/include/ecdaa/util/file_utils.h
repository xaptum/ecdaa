/******************************************************************************
 *
 * Copyright 2017 Xaptum, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/
#ifndef ECDAA_UTIL_FILE_UTIL_H
#define ECDAA_UTIL_FILE_UTIL_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>



/*
 * Read at-most `bytes_to_read` bytes from the given file pointer.
 *
 * Reads until `bytes_to_read` bytes have been read, or until `EOF`, whichever comes first.
 *
 * Returns:
 * Number of bytes read into `buffer` on success
 * READ_FROM_FILE_ERROR on failure
*/
int ecdaa_read_from_fp(unsigned char* buffer, size_t bytes_to_read, FILE *f);

/*
 * Writes given byte-string to the given file_pointer.
 *
 * Returns:
 * 'bytes_to_write' on success
 * WRITE_TO_FILE_ERROR on failure
*/
int ecdaa_write_buffer_to_fp(FILE *f, uint8_t *buffer, size_t bytes_to_write);

/*
 * Read at-most `bytes_to_read` bytes from the given file.
 *
 * Reads until `bytes_to_read` bytes have been read, or until `EOF`, whichever comes first.
 *
 * Returns:
 * Number of bytes read into `buffer` on success
 * READ_FROM_FILE_ERROR on failure
*/
int ecdaa_read_from_file(unsigned char *buffer, size_t bytes_to_read, const char *filename);

/*
 * Writes given byte-string to the given file.
 *
 * Returns:
 * 'bytes_to_write' on success
 * WRITE_TO_FILE_ERROR on failure
*/
int ecdaa_write_buffer_to_file(const char *filename, uint8_t *buffer, size_t bytes_to_write);



#ifdef __cplusplus
}
#endif

#endif
