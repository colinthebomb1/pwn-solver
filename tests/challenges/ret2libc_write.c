/* Minimal ROP challenge: writable memory + system@plt, but no /bin/sh string. */

#include <stdio.h>
#include <stdlib.h>

char scratch[32];

void __attribute__((used, naked)) _gadgets(void) {
    __asm__("pop %rdi; ret");
}

void __attribute__((used)) _force_plt(void) {
    if (getenv("NEVER_SET_ENV_VAR")) {
        system(getenv("NEVER_SET_ENV_VAR"));
    }
}

static void vuln(void) {
    char buf[64];

    puts("input:");
    gets(buf);
    puts("done");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    return 0;
}
