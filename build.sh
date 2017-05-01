#!/bin/sh
gcc -shared libertyhook.c libertyhookasm.S -o libertyhook.so -m32 -ldl
