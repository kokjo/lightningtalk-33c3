#!/bin/sh
gcc -m32 pwnable.c -Wl,-zexecstack -o pwnable
docker build --no-cache -t lightning-pwnable .
