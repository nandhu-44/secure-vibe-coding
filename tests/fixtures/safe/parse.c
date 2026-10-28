#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int greet(const char *name) {
    char buf[32];
    int n = snprintf(buf, sizeof buf, "hi %s", name);
    if (n < 0 || (size_t)n >= sizeof buf) return -1;
    printf("%s\n", buf);
    return 0;
}

void *alloc_items(size_t count, size_t size) {
    return calloc(count, size);
}

void wipe(char *secret_key, size_t n) {
    explicit_bzero(secret_key, n);
}

long parse_long(const char *s, int *ok) {
    char *end = NULL;
    long v = strtol(s, &end, 10);
    *ok = (end != s && *end == '\0');
    return v;
}
