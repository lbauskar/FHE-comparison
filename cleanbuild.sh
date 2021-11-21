#!/bin/bash

# build Microsoft SEAL
cd SEAL
cmake -S . -B build
cmake --build build
cd ..

# build HEAAN
cd HEAAN/HEAAN/lib
make
cd ../../..

# build our program
cmake -S . -B build
cmake --build build
