#include "seal_calc.hpp"

using namespace seal;
using std::vector;

SealCalc::SealCalc() {
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_mod_degree = 16384;
    params.set_poly_modulus_degree(poly_mod_degree);
    params.set_coeff_modulus(CoeffModulus::Create(
        poly_mod_degree, {60, 40, 40, 40, 40, 40, 40, 40, 60}));

    this->scale = pow(2.0, 40);
    this->context = SEALContext(params);

    this->encoder = std::make_unique<CKKSEncoder>(context);
    this->evaluator = std::make_unique<Evaluator>(context);

    KeyGenerator keygen(context);
    this->secret_key = keygen.secret_key();
    keygen.create_public_key(public_key);
    keygen.create_galois_keys(galois_keys);
    keygen.create_relin_keys(relin_keys);
}

Ciphertext SealCalc::encrypt(const vector<double> &input) const {

    if (encoder->slot_count() < input.size()) {
        printf("vector too large to encode\n");
        return Ciphertext();
    }

    Plaintext ptext;
    encoder->encode(input, scale, ptext);
    Encryptor encryptor(context, public_key);
    Ciphertext ctext;
    encryptor.encrypt(ptext, ctext);
    return ctext;
}

Ciphertext SealCalc::mean(Ciphertext cipher_text,
                          const size_t num_elements) const {

    Ciphertext sum = cipher_text;
    for (size_t i = encoder->slot_count() / 2; i > 0; i /= 2) {
        evaluator->rotate_vector_inplace(cipher_text, i, galois_keys);
        evaluator->add_inplace(sum, cipher_text);
        cipher_text = sum;
    }
    // each element of sum is now the sum of the original elements of
    // cipher_text

    Plaintext divisor;
    encoder->encode(1.0 / num_elements, scale,
                    divisor); // each element in sum is the mean
    evaluator->multiply_plain_inplace(sum, divisor);
    evaluator->relinearize_inplace(sum, relin_keys);
    evaluator->rescale_to_next_inplace(sum);
    sum.scale() = this->scale; // close enough that we can fudge
    return sum;
}

Ciphertext SealCalc::variance(Ciphertext cipher_text, Ciphertext mean,
                              const size_t num_elements) const {

    Ciphertext var; // each element is (x - mean)
    evaluator->mod_switch_to_inplace(cipher_text, mean.parms_id());
    evaluator->sub(cipher_text, mean, var);
    evaluator->square_inplace(var);
    evaluator->relinearize_inplace(var, relin_keys);
    evaluator->rescale_to_next_inplace(var);

    // multiply by {1, 1, 1, 0, ... , 0} to prevent extraneous elements from
    // messing up variance
    Ciphertext c2 = encrypt([num_elements, this]() {
        vector<double> v(encoder->slot_count(), 0);
        for (int i = 0; i < num_elements; ++i)
            v[i] = 1;
        return v;
    }());
    evaluator->mod_switch_to_inplace(c2, var.parms_id());
    evaluator->multiply_inplace(var, c2);
    evaluator->relinearize_inplace(var, relin_keys);

    // sum up everything for variance
    for (int i = encoder->slot_count() / 2; i > 0; i /= 2) {
        Ciphertext rotated;
        evaluator->rotate_vector(var, i, galois_keys, rotated);
        evaluator->add_inplace(var, rotated);
    }

    // divide by number of elements
    Plaintext divisor;
    encoder->encode(1.0 / num_elements, this->scale, divisor);
    evaluator->mod_switch_to_inplace(divisor, var.parms_id());
    evaluator->multiply_plain_inplace(var, divisor);
    evaluator->relinearize_inplace(var, relin_keys);
    evaluator->rescale_to_next_inplace(var);
    return var;
}

Ciphertext SealCalc::gmi(Ciphertext mean) const {
    Plaintext p;
    encoder->encode(0.02392, this->scale, p);
    evaluator->mod_switch_to_inplace(p, mean.parms_id());
    evaluator->multiply_plain_inplace(mean, p);
    evaluator->relinearize_inplace(mean, relin_keys);
    evaluator->rescale_to_next_inplace(mean);
    mean.scale() = this->scale;

    encoder->encode(3.31, this->scale, p);
    evaluator->mod_switch_to_inplace(p, mean.parms_id());
    evaluator->add_plain_inplace(mean, p);
    return mean;
}

Ciphertext SealCalc::ea1c(Ciphertext mean) const {
    Plaintext p;
    encoder->encode(46.7, this->scale, p);
    evaluator->mod_switch_to_inplace(p, mean.parms_id());
    evaluator->add_plain_inplace(mean, p);
    mean.scale() = this->scale;

    encoder->encode(1 / 28.7, this->scale, p);
    evaluator->mod_switch_to_inplace(p, mean.parms_id());
    evaluator->multiply_plain_inplace(mean, p);
    evaluator->relinearize_inplace(mean, relin_keys);
    evaluator->rescale_to_next_inplace(mean);
    return mean;
}

vector<double> SealCalc::decrypt(const Ciphertext &cipher_text,
                                 const size_t num_elements) const {
    Plaintext ptext;
    Decryptor decryptor(context, secret_key);
    decryptor.decrypt(cipher_text, ptext);

    vector<double> result;
    encoder->decode(ptext, result);
    result.resize(num_elements);
    return result;
}
