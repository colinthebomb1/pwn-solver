/* ret2libc_pie_canary_real — staged ret2libc with PIE + NX + stack canary.
   The binary intentionally leaks:
     - main() address for PIE base
     - current stack canary value
   so the solver can focus on canary-aware payload construction.
*/

#include <stdio.h>
#include <unistd.h>

/* Provide a pop rdi; ret gadget in the main executable. */
void __attribute__((used, naked)) _gadgets(void) {
    __asm__("pop %rdi; ret");
}

void vuln(void) {
    char buf[64];

    puts("name?");
    read(0, buf, 400);
    puts("bye");
}

int main(void) {
    unsigned long canary = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    __asm__("mov %%fs:0x28, %0" : "=r"(canary));
    printf("main is at %p\n", (void *)main);
    printf("canary is 0x%lx\n", canary);
    puts("ret2libc-pie-canary-real");

    vuln();
    return 0;
}
