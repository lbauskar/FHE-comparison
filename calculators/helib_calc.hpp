#ifndef CALCULATORS_HELIB_CALC
#define CALCULATORS_HELIB_CALC

#include <helib/helib.h>

class HelibCalc {
  public:
    HelibCalc();
    helib::Ctxt encrypt(const std::vector<double> &input) const;
    std::vector<double> decrypt(const helib::Ctxt cipher_text,
                                const size_t num_elements) const;
    helib::Ctxt mean(helib::Ctxt cipher_text, const size_t num_elements) const;
    helib::Ctxt gmi(helib::Ctxt mean) const;
    helib::Ctxt ea1c(helib::Ctxt mean) const;

  private:
    const int m = 32768;      // mod size
    const int bits = 358;     // num bits
    const int precision = 40; // scaling factor
    const int c = 6;          // columns for key-switching

    helib::Context context = helib::ContextBuilder<helib::CKKS>()
                                 .m(m)
                                 .bits(bits)
                                 .precision(precision)
                                 .c(c)
                                 .build();
    helib::SecKey secret_key = helib::SecKey(context);
    helib::PubKey &public_key = secret_key;
};

#endif