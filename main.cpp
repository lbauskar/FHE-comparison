#include "ckks_example.h"
#include "fhe_libs.h"
#include "seal/seal.h"

#include "calculators/seal_calc.hpp"
#include <numeric>

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
    Context context = ContextBuilder<CKKS>()
                          .m(16 * 1024)
                          .bits(119)
                          .precision(30)
                          .c(2)
                          .build();
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
    printf("c.capacity = %f\nc.errorBound = %f\n", c.capacity(),
           c.errorBound());

    // make nxn plaintext matrix
    MatMul_CKKS mat(context,
                    [n](long i, long j) { return ((i + j) % n) / double(n); });
    c *= mat;
    printf("c.capacity = %f\nc.errorBound = %f\n", c.capacity(),
           c.errorBound());

    p *= mat;
    PtxtArray pp(context);
    pp.decrypt(c, secretKey);
    printf("distance=%f\n", Distance(p, pp));
}

double fRand(const double fMin, const double fMax) {
    double f = (double)rand() / RAND_MAX;
    return fMin + f * (fMax - fMin);
}

void sealCalcTest() {
    using std::vector;
    srand(time(NULL));
    vector<double> v(20);

    const auto rand = []() { return fRand(-10, 10); };
    const auto printVec = [](const vector<double> &v) {
        for (double d : v) {
            printf("%f, ", d);
        }
        printf("\n");
    };

    for (double &d : v) {
        d = rand();
    }
    printVec(v);

    SealCalc calc;
    seal::Ciphertext c = calc.encrypt(v);
    vector<double> v2 = calc.decrypt(c, v.size());
    printVec(v2);

    seal::Ciphertext mean_c = calc.mean(c, v.size());
    vector<double> mean = calc.decrypt(mean_c, v.size());
    printf("calc mean: %f, real mean: %f\n", mean[0], [&v]() {
        double sum = 0;
        for (double d : v)
            sum += d;
        return sum / v.size();
    }());

    double var_d = [&v, &mean]() {
        double sum = 0;
        for (int i = 0; i < v.size(); ++i) {
            sum += (v[i] - mean[i]) * (v[i] - mean[i]);
        }

        sum /= v.size();
        return sum;
    }();
    auto var_c = calc.variance(c, mean_c, v.size());
    auto var_v = calc.decrypt(var_c, v.size());
    printf("cal var: %f, real var: %f\n", var_v[0], var_d);

    auto gmi_c = calc.gmi(mean_c);
    auto ea1c_c = calc.ea1c(mean_c);

    auto gmi_v = calc.decrypt(gmi_c, 1);
    auto ea1c_v = calc.decrypt(ea1c_c, 1);

    printf("gmi: %f, ea1c: %f\n", gmi_v[0], ea1c_v[0]);
}

int main() {
    // example_ckks_basics();
    // heaanMult(800, 30, 4);
    // helibMult();
    sealCalcTest();
    return 0;
}