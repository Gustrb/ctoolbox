#pragma once
#ifndef CTOOLBOX_STRING_H
#define CTOOLBOX_STRING_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#define ARENA_IMPLEMENTATION
#include "arena.h"

typedef struct {
    uint8_t *data;
    size_t count;
    size_t capacity;
} string_builder_t;

typedef struct {
    string_builder_t *data;
    size_t count;
    size_t capacity;
} string_list_t;

void sb_push_byte(arena_t *a, string_builder_t *sb, uint8_t byte);
void sb_push_bytes(arena_t *a, string_builder_t *sb, size_t count, ...);
void sb_push_int(arena_t *a, string_builder_t *sb, int i);

void sb_push_cstring(arena_t *a, string_builder_t *sb, const char *str);

char *sb_build_cstring(arena_t *a, string_builder_t sb);

#ifdef STR_IMPLEMENTATION

#include <string.h>
#include <stdlib.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

void sb_push_byte(arena_t *arena, string_builder_t *sb, uint8_t byte)
{
    if (sb->count == sb->capacity) {
        sb->capacity = MAX(sb->capacity * 2, 64);
        sb->data = (uint8_t *)arena_realloc(arena, sb->data, sb->capacity);
    }

    sb->data[sb->count++] = byte;
}

void sb_push_bytes(arena_t *a, string_builder_t *sb, size_t count, ...)
{
    va_list args;
    va_start(args, count);

    for (size_t i = 0; i < count; i++) {
        sb_push_byte(a, sb, va_arg(args, int));
    }

    va_end(args);
}

void sb_push_cstring(arena_t *a, string_builder_t *sb, const char *str)
{
    size_t len = strlen(str);
    if (sb->count + len >= sb->capacity) {
        sb->capacity = MAX(sb->capacity * 2, 64);
        sb->data = (uint8_t *)arena_realloc(a, sb->data, sb->capacity);
    }

    memcpy(sb->data + sb->count, str, len);
    sb->count += len;
}

char *sb_build_cstring(arena_t *a, string_builder_t sb)
{
    char *result = (char *)arena_alloc(a, sb.count + 1);
    memcpy(result, sb.data, sb.count);
    result[sb.count] = '\0';
    return result;
}

void sb_push_int(arena_t *a, string_builder_t *sb, int i)
{
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%d", i);
    for (int j = 0; j < len; j++) {
        sb_push_byte(a, sb, buf[j]);
    }
}

#endif // STR_IMPLEMENTATION

#endif // CTOOLBOX_STRING_H
