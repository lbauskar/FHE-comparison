#include "ckks_example.h"
#include "fhe_libs.h"
#include "seal/seal.h"

void heaanMult(long logq, long logp, long logn) {
  using std::complex, std::cout, std::endl;
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

void helibMult() {
  puts("Begin HElib mult test");
  using namespace helib;
  using namespace std;

  // make secret key
  Context context =
      ContextBuilder<CKKS>().m(16 * 1024).bits(119).precision(30).c(2).build();
  long n = context.getNSlots();
  SecKey secretKey(context);
  secretKey.GenSecKey();

  // make public key
  addSome1DMatrices(secretKey);
  const PubKey &publicKey = secretKey;

  // encrypt array
  vector<double> v(n);
  for (int i = 0; i < n; ++i) {
    v[i] = sin(2 * PI * i / n);
  }
  PtxtArray p(context, v);
  Ctxt c(publicKey);
  p.encrypt(c);
  printf("c.capacity = %f\nc.errorBound = %f\n", c.capacity(), c.errorBound());

  // make nxn plaintext matrix
  MatMul_CKKS mat(context,
                  [n](long i, long j) { return ((i + j) % n) / double(n); });
  c *= mat;
  printf("c.capacity = %f\nc.errorBound = %f\n", c.capacity(), c.errorBound());

  p *= mat;
  PtxtArray pp(context);
  pp.decrypt(c, secretKey);
  printf("distance=%f\n", Distance(p, pp));
}

int main() {
  example_ckks_basics();
  heaanMult(800, 30, 4);
  helibMult();
  return 0;
}