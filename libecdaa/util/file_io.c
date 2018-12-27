/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
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
 #include <stdint.h>
 #include <stdio.h>
 #include <ecdaa/util/file_io.h>
 #include <ecdaa/util/errors.h>

int ecdaa_read_from_file(unsigned char *buffer, size_t bytes_to_read, const char *filename)
{
    FILE *file_ptr = fopen(filename, "rb");

    if (NULL == file_ptr){
        return READ_FROM_FILE_ERROR;
    }

    int ret = ecdaa_read_from_fp(buffer, bytes_to_read, file_ptr);

    if (ret >= 0 && bytes_to_read == (size_t)ret) {
        if (0 != fclose(file_ptr)) {
            return READ_FROM_FILE_ERROR;
        }
    }

    return ret;
 }

int ecdaa_write_buffer_to_file(const char *filename, uint8_t *buffer, size_t bytes_to_write)
{
    FILE *file_ptr = fopen(filename, "wb");

    if (NULL == file_ptr){
        return WRITE_TO_FILE_ERROR;
    }

    int ret = ecdaa_write_buffer_to_fp(file_ptr, buffer, bytes_to_write);

    if (ret >= 0 && bytes_to_write == (size_t)ret) {
        if (0 != fclose(file_ptr)) {
            return WRITE_TO_FILE_ERROR;
        }
    }

    return ret;
}

int ecdaa_read_from_fp(unsigned char *buffer, size_t bytes_to_read, FILE *file_ptr)
{
    if (NULL == file_ptr){
        return READ_FROM_FILE_ERROR;
    }

    size_t bytes_read = fread(buffer, 1, bytes_to_read, file_ptr);

    if (bytes_to_read != bytes_read && !feof(file_ptr)) {
       return READ_FROM_FILE_ERROR;
    }

    fgetc(file_ptr);
    if (!feof(file_ptr)){
        return READ_FROM_FILE_ERROR;
    }

    return (int)bytes_read;
 }

 int ecdaa_write_buffer_to_fp(FILE *file_ptr, uint8_t *buffer, size_t bytes_to_write)
 {
    if (NULL == file_ptr){
        return WRITE_TO_FILE_ERROR;
    }

    size_t bytes_written = fwrite(buffer, 1, bytes_to_write, file_ptr);

    if (bytes_to_write != bytes_written) {
        return WRITE_TO_FILE_ERROR;
    }

    return (int)bytes_written;
 }
