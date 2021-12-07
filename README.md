## FHE Comparison (Cryptography Project)

This code is just a small benchmark suite for Microsoft SEAL, HEANN, and HElib that compares the speed of their CKKS implementations.
To build everything just run `sh cleanbuild.sh` in your terminal. This will install the libraries, compile them, then compile the benchmarking code.
You can then run the actual benchmarking code with `build/fhe-test`.

I only ran this on Linux. It probably does not work on MacOS and definitely won't run on Windows.
