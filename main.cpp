#include "HEAAN.h"
#include "ckks_example.h"
#include "seal/seal.h"

using std::complex, std::cout, std::endl;

void heaanMult(long logq, long logp, long logn) {
  cout << "!!! START TEST MULT !!!" << endl;

  srand(time(NULL));
  NTL::SetNumThreads(8);
  TimeUtils timeutils;
  Ring ring;
  SecretKey secretKey(ring);
  Scheme scheme(secretKey, ring);

  long n = (1 << logn);
  complex<double> *mvec1 = EvaluatorUtils::randomComplexArray(n);
  complex<double> *mvec2 = EvaluatorUtils::randomComplexArray(n);
  complex<double> *mmult = new complex<double>[n];
  for (long i = 0; i < n; i++) {
    mmult[i] = mvec1[i] * mvec2[i];
  }

  Ciphertext cipher1, cipher2;
  scheme.encrypt(cipher1, mvec1, n, logp, logq);
  scheme.encrypt(cipher2, mvec2, n, logp, logq);

  timeutils.start("Multiplication");
  scheme.multAndEqual(cipher1, cipher2);
  timeutils.stop("Multiplication");

  complex<double> *dmult = scheme.decrypt(secretKey, cipher1);
  ;
  StringUtils::compare(mmult, dmult, n, "mult");

  cout << "!!! END TEST MULT !!!" << endl;
}

int main() {
  example_ckks_basics();
  heaanMult(800, 30, 4);
  return 0;
}