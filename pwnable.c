#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){
    setvbuf(stdout, NULL, _IOLBF, 0);
    char *name = malloc(100);
    char buffer[128] = {0};

    printf("Hello, i'm a very simple pwnable. What's your name?\n");

    gets(name); // BUG 1!
    printf("Hi, %s\n", name);

    while(strcmp(buffer, "quit")){
        printf("Write me something and I will printf it for you!\n");
        gets(buffer); // BUG, 2!
        printf(buffer); // BUG 3!
    }

    printf("bye bye %s\n", name);
    free(name); // <- Goal, make free be like system

    return 0;
}
