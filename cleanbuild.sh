#!/bin/bash

# get library files
git submodule update --remote

# build Microsoft SEAL
cd SEAL
rm -rf build
cmake -S . -B build
cmake --build build
cd ..

# build HEAAN
cd HEAAN/HEAAN/lib
make
cd ../../..

#build HElib
cd HElib
rm -rf build
mkdir build
cd build
cmake -DPACKAGE_BUILD=ON -DCMAKE_INSTALL_PREFIX=helib_install ..
make -j8
make install
cd ../..

# build our program
cmake -S . -B build
cmake --build build
