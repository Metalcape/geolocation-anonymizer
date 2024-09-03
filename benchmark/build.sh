#! /bin/bash

# Build library
g++ -fPIC -std=c++17 -fopenmp -g -c bfv.cpp -o libbfv.o -I/usr/local/include/SEAL-4.1 -lseal-4.1 -ltbb
g++ -fPIC -std=c++17 -fopenmp -g -c bfvcuda.cpp -o libbfvcuda.o -I../troy-nova/src/ -I/usr/local/cuda/include -L/usr/local/cuda/lib64 -ltroy -lcudart -ltbb
g++ -fPIC -std=c++17 -g -c util.cpp -o libutil.o -I/usr/local/include/SEAL-4.1 -I../troy-nova/src/ -I/usr/local/cuda/include -lseal-4.1 -ltroy
g++ -shared -g libbfv.o libutil.o libbfvcuda.o libbfv.h libbfvcuda.h -o libbfv.so -I/usr/local/include/SEAL-4.1 -I../troy-nova/src/ -I/usr/local/cuda/include -L/usr/local/cuda/lib64 -lseal-4.1 -ltroy -lcudart
# g++ -shared libbfv.o libbfv_extern.h -o libbfv_extern.so -I/usr/local/include/SEAL-4.1 -lseal-4.1

# Build main for testing
g++ -std=c++17 -fopenmp -g main.cpp ./libbfv.so -isystem benchmark/include -lbenchmark -lpthread -I/usr/local/include/SEAL-4.1 -I../troy-nova/src/ -I/usr/local/cuda/include -L/usr/local/cuda/lib64 -lseal-4.1 -ltroy -ltbb -lcudart -o main.out