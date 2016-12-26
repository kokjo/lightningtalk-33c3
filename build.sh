#!/bin/sh
gcc -m32 pwnable.c -Wl,-zexecstack -o pwnable
docker build -t lightning-pwnable .
