/* ret2win — simplest possible pwn challenge.
   Buffer overflow with a win function that's never called. */

#include <stdio.h>
#include <stdlib.h>

void win() {
    puts("FLAG{you_win_ret2win}");
    exit(0);
}

void vuln() {
    char buf[64];
    puts("Enter your name:");
    gets(buf);
    printf("Hello, %s!\n", buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    return 0;
}
