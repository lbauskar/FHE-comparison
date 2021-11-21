## Building Microsoft SEAL

Type the following into the terminal to build the Microsoft SEAL library.

```Bash
cd SEAL
cmake -S . -B build
cmake --build build
```

Link this library with the `gcc` argument `-llibseal-3.7 -LSEAL/build/lib`.
