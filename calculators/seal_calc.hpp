#ifndef CALCULATORS_SEAL_CALC
#define CALCULATORS_SEAL_CALC

#include "seal/seal.h"
#include <vector>

class SealCalc {
  public:
    SealCalc();
    seal::Ciphertext encrypt(const std::vector<double> &input) const;
    std::vector<double> decrypt(const seal::Ciphertext &cipher_text,
                                const size_t num_elements) const;
    seal::Ciphertext mean(seal::Ciphertext cipher_text,
                          const size_t num_elements) const;
    seal::Ciphertext variance(seal::Ciphertext cipher_text,
                              seal::Ciphertext mean,
                              const size_t num_elements) const;
    seal::Ciphertext gmi(seal::Ciphertext mean) const;
    seal::Ciphertext ea1c(seal::Ciphertext mean) const;

  private:
    double scale = 0;

    seal::SEALContext context =
        seal::SEALContext(seal::EncryptionParameters(seal::scheme_type::ckks));
    seal::SecretKey secret_key;
    seal::PublicKey public_key;
    seal::GaloisKeys galois_keys;
    seal::RelinKeys relin_keys;

    std::unique_ptr<seal::CKKSEncoder> encoder = nullptr;
    std::unique_ptr<seal::Evaluator> evaluator = nullptr;
};

#endif