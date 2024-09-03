#! /bin/bash

cd troy-nova
mkdir -p build
cd build
cmake .. -DCMAKE_CUDA_ARCHITECTURES=86    # Change this to match your GPU architecture
make troy
