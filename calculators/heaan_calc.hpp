#ifndef CALCULATORS_HEAAN_CALC
#define CALCULATORS_HEAAN_CALC

#include "../HEAAN/HEAAN/src/HEAAN.h"
#include <vector>

class HeaanCalc {
  public:
    HeaanCalc();
    Ciphertext encrypt(std::vector<std::complex<double>> &input) const;
    std::vector<std::complex<double>> decrypt(const Ciphertext cipher_text,
                                              const size_t num_elements) const;
    Ciphertext mean(Ciphertext cipher_text, const size_t num_elements) const;
    Ciphertext gmi(Ciphertext mean) const;
    Ciphertext ea1c(Ciphertext mean) const;

  private:
    const int logq = 800; // mod size
    const int logp = 40;  // scaling factor
    const int logn = 12;  // power of 2 slots
    const size_t slots = 1 << logn;

    Ring ring;
    std::unique_ptr<Scheme> scheme = nullptr;
    std::unique_ptr<SecretKey> secret_key = nullptr;
};

#endif