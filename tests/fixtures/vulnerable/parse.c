#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void greet(const char *name) {
    char buf[32];
    strcpy(buf, name); /* expect: SV-MEM-001 */
    sprintf(buf, "hi %s", name); /* expect: SV-MEM-001 */
    printf(name); /* expect: SV-MEM-003 */
}

int read_input(void) {
    char line[64];
    scanf("%s", line); /* expect: SV-MEM-002 */
    return atoi(line); /* expect: SV-MEM-007 */
}

void *alloc_items(size_t count, size_t size) {
    return malloc(count * size); /* expect: SV-MEM-006 */
}

void wipe(char *secret_key, size_t n) {
    memset(secret_key, 0, n); /* expect: SV-MEM-004 */
}

void run(const char *cmd) {
    system(cmd); /* expect: SV-MEM-005 */
}
