#! /bin/bash

# Build library
g++ -fPIC -c bfv.cpp -o libbfv.o -I/usr/local/include/SEAL-4.1 -lseal-4.1
g++ -fPIC -c util.cpp -o libutil.o -I/usr/local/include/SEAL-4.1 -lseal-4.1
g++ -shared libbfv.o libutil.o libbfv.h -o libbfv.so -I/usr/local/include/SEAL-4.1 -lseal-4.1
# g++ -shared libbfv.o libbfv_extern.h -o libbfv_extern.so -I/usr/local/include/SEAL-4.1 -lseal-4.1

# Build main for testing
g++ -g main.cpp ./libbfv.so -isystem benchmark/include -lbenchmark -lpthread -I/usr/local/include/SEAL-4.1 -lseal-4.1 -o main.out