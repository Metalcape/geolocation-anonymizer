#! /bin/bash

# Build library
g++ -fPIC -std=c++17 -fopenmp -g -c bfv.cpp -o libbfv.o -I/usr/local/include/SEAL-4.1 -lseal-4.1 -ltbb
g++ -fPIC -std=c++17 -g -c util.cpp -o libutil.o -I/usr/local/include/SEAL-4.1 -lseal-4.1
g++ -shared libbfv.o libutil.o libbfv.h -o libbfv.so -I/usr/local/include/SEAL-4.1 -lseal-4.1
# g++ -shared libbfv.o libbfv_extern.h -o libbfv_extern.so -I/usr/local/include/SEAL-4.1 -lseal-4.1

# Build main for testing
g++ -std=c++17 -fopenmp -g main.cpp ./libbfv.so -isystem benchmark/include -lbenchmark -lpthread -I/usr/local/include/SEAL-4.1 -lseal-4.1 -ltbb -o main.out