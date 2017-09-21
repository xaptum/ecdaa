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

#include <stdint.h>
#include <stdio.h>

static int read_file_into_buffer(uint8_t *buffer, size_t bytes_to_read, const char *filename) {
    FILE *ptr;

    ptr = fopen(filename, "rb");
    if (NULL == ptr)
        return -1;

    if (fread(buffer, 1, bytes_to_read, ptr) != bytes_to_read)
        return -1;

    (void)fclose(ptr);

    return 0;
}

static int write_buffer_to_file(const char *filename, uint8_t *buffer, size_t bytes_to_write)
{
    FILE *ptr;

    ptr = fopen(filename, "wb");
    if (NULL == ptr)
        return -1;

    if (fwrite(buffer, 1, bytes_to_write, ptr) != bytes_to_write)
        return -1;

    (void)fclose(ptr);

    return 0;
}
