#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){
    setvbuf(stdout, NULL, _IOLBF, 0);
    char *name = malloc(100);
    char buffer[128] = {0};
    printf("What's your name?\n");
    gets(name); // Heap overflow
    printf("Hi, %s\n", name);
    while(strcmp(buffer, "quit")){
        printf("What's to printf today?\n");
        gets(buffer); // Stack overflow
        printf(buffer); // Format string exploit
    }
    free(name); // <- Goal, make free be like system
    return 0;
}
