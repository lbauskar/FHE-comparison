#include "helib_calc.hpp"

using namespace helib;
using std::vector;

HelibCalc::HelibCalc() {
    secret_key.GenSecKey();
    addSome1DMatrices(secret_key);
}

Ctxt HelibCalc::encrypt(const vector<double> &input) const {
    PtxtArray p_arr(context, input);
    Ctxt c(public_key);
    p_arr.encrypt(c);
    return c;
}

Ctxt HelibCalc::mean(Ctxt cipher_text, const size_t num_elems) const {
    Ctxt sum = cipher_text;
    totalSums(sum);
    sum *= (1.0 / num_elems);
    return sum;
}

Ctxt HelibCalc::ea1c(Ctxt mean) const {
    mean += 46.7;
    mean *= (1 / 28.7);
    return mean;
}

Ctxt HelibCalc::gmi(Ctxt mean) const {
    mean *= 0.02392;
    mean += 3.31;
    return mean;
}

vector<double> HelibCalc::decrypt(Ctxt cipher_text,
                                  const size_t num_elems) const {
    PtxtArray p_arr(context);
    p_arr.decrypt(cipher_text, secret_key);
    vector<double> v;
    p_arr.store(v);
    v.resize(num_elems);
    return v;
}