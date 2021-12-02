#include "heaan_calc.hpp"

using std::complex;
using std::vector;

HeaanCalc::HeaanCalc() {
    srand(time(NULL));
    SetNumThreads(8);
    this->secret_key = std::make_unique<SecretKey>(this->ring);
    this->scheme = std::make_unique<Scheme>(*secret_key, ring);
    scheme->addLeftRotKeys(*secret_key);
    scheme->addRightRotKeys(*secret_key);
}

Ciphertext HeaanCalc::encrypt(vector<complex<double>> &input) const {
    if (slots < input.size()) {
        return Ciphertext();
    } else if (slots > input.size()) {
        input.resize(slots, 0);
    }

    Ciphertext cipher_text;
    scheme->encrypt(cipher_text, input.data(), slots, logp, logq);
    return cipher_text;
}

vector<complex<double>> HeaanCalc::decrypt(Ciphertext cipher_text,
                                           const size_t num_elements) const {
    complex<double> *arr = scheme->decrypt(*secret_key, cipher_text);
    vector<complex<double>> v(arr, arr + num_elements);
    return v;
}

Ciphertext HeaanCalc::mean(Ciphertext cipher_text,
                           const size_t num_elements) const {
    Ciphertext sum = cipher_text;
    for (int n = slots / 2; n > 0; n /= 2) {
        scheme->rightRotateFast(cipher_text, sum, n);
        scheme->addAndEqual(sum, cipher_text);
    }

    complex<double> divisor(1.0 / num_elements, 0);
    scheme->multByConstAndEqual(sum, divisor, logp);
    return sum;
}

Ciphertext HeaanCalc::gmi(Ciphertext mean) const {
    complex<double> c(0.02932, 0);
    scheme->multByConstAndEqual(mean, c, logp);
    scheme->reScaleByAndEqual(mean, 2 * logp);
    c = complex<double>(3.31, 0);
    scheme->addConstAndEqual(mean, c, logp);

    return mean;
}

Ciphertext HeaanCalc::ea1c(Ciphertext mean) const {
    Ciphertext adder;
    scheme->encryptSingle(adder, 46.7, mean.logp, mean.logq);
    scheme->addAndEqual(mean, adder);

    complex<double> c(1 / 28.7, 0);
    scheme->multByConstAndEqual(mean, c, logp);
    return mean;
}