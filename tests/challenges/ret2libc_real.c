/* ret2libc_real — modeled after common CTF "babyrop" flow.
   Stage 1: leak puts@GLIBC via puts(puts@got), return to main.
   Stage 2: call system("/bin/sh") in libc.
   No /bin/sh string or system@plt in this binary. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Ensure a reliable pop rdi; ret gadget exists in tiny binaries. */
void __attribute__((used, naked)) _gadgets(void) {
    __asm__("pop %rdi; ret");
}

static void vuln(void) {
    char buf[64];

    puts("name?");
    /* Deliberate overflow primitive for ROP challenges. */
    read(0, buf, 400);
    puts("bye");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("ret2libc-real");
    vuln();
    return 0;
}

