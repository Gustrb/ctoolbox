#pragma once
#ifndef CTOOLBOX_TOOLBOX_H
#define CTOOLBOX_TOOLBOX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

enum arena_flags {
	ARENA_GROW = 1 << 0,
	ARENA_DONTALIGN = 1 << 1,
};

typedef struct arena {
	char *data;
	size_t size;
	size_t cap;
	char flags;
} arena_t;

/*
 * Allocate a new arena. The underlying mem is allocated through mmap.
 * Errors can be checked with `arena_new_failed`
 */
arena_t arena_new();

/*
 * Delete memory mapped for arena a.
 * should only be used with arenas created from `arena_new` 
 * Returns 0 on success, 1 on failure
*/
uint8_t arena_delete(arena_t *a);

static inline arena_t arena_attach(void *ptr, size_t size);
static inline void *arena_detach(arena_t arena);
static inline uint8_t arena_new_failed(arena_t *a);
static inline void arena_reset(arena_t *a);

void *arena_alloc(arena_t *a, size_t len);
void *arena_calloc(arena_t *a, size_t nmemb, size_t size);
void *arena_realloc(arena_t *a, void *ptr, size_t size);

typedef struct {
    uint8_t *data;
    size_t count;
    size_t capacity;
} string_builder_t;

void sb_push_byte(arena_t *a, string_builder_t *sb, uint8_t byte);
void sb_push_bytes(arena_t *a, string_builder_t *sb, size_t count, ...);
void sb_push_int(arena_t *a, string_builder_t *sb, int i);

void sb_push_cstring(arena_t *a, string_builder_t *sb, const char *str);

char *sb_build_cstring(arena_t *a, string_builder_t sb);

#define ERR_FAILED_TO_OPEN_FILE 1
#define ERR_FAILED_TO_READ_FILE 2
#define ERR_FAILED_TO_WRITE_TO_FILE 3

uint8_t io_read_file_into_sb(arena_t *a, string_builder_t *sb, const char *filepath);
uint8_t io_write_sb_to_file(string_builder_t sb, const char *filepath);

#ifdef TOOLBOX_IMPLEMENTATION

#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#define KNOB_MMAP_SIZE (1UL << 36UL)
#define KNOB_ALIGNMENT (sizeof(char*))

#define MAX(a, b) ((a) > (b) ? (a) : (b))


static inline arena_t arena_attach(void *ptr, size_t size)
{
	return (arena_t) { .data = (char *)ptr, .size = 0, .cap = size, .flags = 0 };
}

static inline void *arena_detach(arena_t arena)
{
	return arena.data;
}

static inline uint8_t arena_new_failed(arena_t *a)
{
	return a->data == NULL;
}

static inline void arena_reset(arena_t *a)
{
	a->size = 0;
}

#ifndef NDEBUG
#define arena_err(msg) \
	fprintf(stderr, "%s (%s:%d): %s\n", msg, __func__, __LINE__, strerror(errno))
#else
#define arena_err(msg)
#endif

static uint8_t arena_grow(arena_t *a, size_t min_size)
{
	if (!(a->flags & ARENA_GROW)) {
		return 0;
	}
	size_t new_cap = a->cap * 2;
	while (new_cap < min_size) {
		new_cap *= 2;
	}

	int ok = mprotect(a->data + a->cap, new_cap - a->cap, PROT_READ | PROT_WRITE);
	if (ok == -1) {
		arena_err("mprotect");
		return 0;
	}

	a->cap = new_cap;
	return 1;
}

arena_t arena_new()
{
	size_t size;
	int ok;
	void *p;

	size = sysconf(_SC_PAGE_SIZE);
	if (size == -1) {
		arena_err("sysconf");
		goto sysconf_failed;
	}
	p = mmap(NULL, KNOB_MMAP_SIZE, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (p == MAP_FAILED) {
		arena_err("mmap");
		goto mmap_failed;
	}

	ok = mprotect(p, size, PROT_READ | PROT_WRITE);
	if (ok == -1) {
		arena_err("mprotect");
		goto mprotect_failed;
	}

	arena_t a;
	a = (arena_t){
		.data = (char *) p,
		.size = 0,
		.cap = size,
		.flags = ARENA_GROW
	};

	return a;
mprotect_failed:
	ok = munmap(p, KNOB_MMAP_SIZE);
	if (ok == -1) arena_err("munmap");

mmap_failed:
sysconf_failed:
	return (arena_t){0};
}

void *arena_alloc(arena_t *a, size_t size)
{
	if (!(a->flags & ARENA_DONTALIGN)) {
		size = (size + KNOB_ALIGNMENT - 1) & ~(KNOB_ALIGNMENT - 1);
	}

	void *p = a->data + a->size;
	if (a->size + size > a->cap) {
		if (!arena_grow(a, a->size)) return NULL;
	}
	a->size += size;
	return p;
}

void *arena_calloc(arena_t *a, size_t nmemb, size_t size)
{
	void *p = arena_alloc(a, nmemb * size);
	if (p == NULL) return p;
	memset(p, 0, nmemb * size);
	return p;
}

void *arena_realloc(arena_t *a, void *ptr, size_t size)
{
	if (ptr == NULL) return arena_alloc(a, size);

	size_t offset = (char *)ptr - a->data;
	if (offset + size > a->cap) {
		if (!arena_grow(a, offset + size)) return NULL;
	}

	return a->data + offset;
}

uint8_t arena_delete(arena_t *a)
{
	if (!(a->flags & ARENA_GROW)) return -1;

	int ok = munmap(a->data, KNOB_MMAP_SIZE);
	if (ok == -1) {
		arena_err("munmap");
		return 1;
	}

	a->cap = -1;
	a->size = -1;
	return 0;
}


uint8_t io_read_file_into_sb(arena_t *a, string_builder_t *sb, const char *filepath)
{
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        return ERR_FAILED_TO_OPEN_FILE;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    sb->capacity = file_size;
    sb->data = (uint8_t *)arena_alloc(a, file_size);
    sb->count = file_size;

    if (fread(sb->data, 1, file_size, file) < file_size) {
        fclose(file);
        return ERR_FAILED_TO_READ_FILE;
    }

    fclose(file);

    return 0;
}

uint8_t io_write_sb_to_file(string_builder_t sb, const char *filepath)
{
    FILE *file = fopen(filepath, "wb");
    if (!file) {
        return ERR_FAILED_TO_OPEN_FILE;
    }

    if (fwrite(sb.data, 1, sb.count, file) < sb.count) {
        fclose(file);
        return ERR_FAILED_TO_WRITE_TO_FILE;
    }

    fclose(file);

    return 0;
}


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

#endif

#ifdef __cplusplus
}
#endif

#endif // CTOOLBOX_TOOLBOX_H
