
#include "calculators/heaan_calc.hpp"
#include "calculators/helib_calc.hpp"
#include "calculators/seal_calc.hpp"
#include <chrono>
#include <string>
#include <vector>

struct GlucoseData {
    std::vector<double> bg, cgm, cho, insulin, lbgi, hbgi, risk;
};

GlucoseData readCsv(std::string filename) {
    GlucoseData data;
    FILE *file = fopen(filename.c_str(), "r");

    vector<char> line(1024);
    fgets(line.data(), line.size(), file); // skip first line

    while (fgets(line.data(), line.size(), file)) {
        int year, month, day, hour, minute, second;
        double bg, cgm, cho, insulin, lbgi, hbgi, risk;

        sscanf(line.data(), "%d-%d-%d %d:%d:%d,%lf,%lf,%lf,%lf,%lf,%lf,%lf\n",
               &year, &month, &day, &hour, &minute, &second, &bg, &cgm, &cho,
               &insulin, &lbgi, &hbgi, &risk);

        // printf("%s", line.data());
        // printf("%d-%d-%d %d:%d:%d, %f,%f,%f,%f,%f,%f,%f\n\n", year, month,
        // day,
        //       hour, minute, second, bg, cgm, cho, insulin, lbgi, hbgi, risk);

        data.bg.push_back(bg);
        data.cgm.push_back(cgm);
        data.cho.push_back(cho);
        data.insulin.push_back(insulin);
        data.lbgi.push_back(lbgi);
        data.hbgi.push_back(hbgi);
        data.risk.push_back(risk);
    }

    // get rid of last line because it may be missing fields
    data.bg.pop_back();
    data.cgm.pop_back();
    data.cho.pop_back();
    data.insulin.pop_back();
    data.lbgi.pop_back();
    data.hbgi.pop_back();
    data.risk.pop_back();

    return data;
};

struct GlucoseStats {
    struct Stats {
        double mean, gmi, ea1c;
    };
    Stats bg, cgm, cho, insulin, lbgi, hbgi, risk;
};

void unencryptedSuite(const GlucoseData &data, const int id,
                      const bool csv = true) {
    using std::vector, std::string;
    typedef std::chrono::high_resolution_clock hrc;

    const auto usec = [](decltype(hrc::now()) &start,
                         decltype(hrc::now()) &end) {
        return std::chrono::duration_cast<std::chrono::microseconds>(end -
                                                                     start)
            .count();
    };

    const auto testVector = [&usec, csv, id](const vector<double> &v,
                                             const string &label) {
        auto start = hrc::now();
        // no encryption necessary
        auto enc_time = hrc::now();

        double mean_d = [&v]() {
            double sum = 0;
            for (double d : v)
                sum += d;
            return sum / v.size();
        }();
        auto mean_time = hrc::now();

        double gmi_d = 3.31 + (.02392 * mean_d);
        auto gmi_time = hrc::now();

        double ea1c_d = (46.7 + mean_d) / 28.7;
        auto ea1c_time = hrc::now();

        // no decryption needed
        auto dec_time = hrc::now();

        if (csv) {
            printf(
                "Unencrypted %s %d, %lld, %f, %lld, %f, %lld, %f, %lld, %lld\n",
                label.c_str(), id, usec(start, enc_time), mean_d,
                usec(enc_time, mean_time), gmi_d, usec(mean_time, gmi_time),
                ea1c_d, usec(gmi_time, ea1c_time), usec(ea1c_time, dec_time));
        } else {
            printf("    %s: enc (%lld us), mean=%f (%lld us), gmi=%f (%lld "
                   "us), "
                   "ea1c=%f (%lld us), dec (%lld us)\n",
                   label.c_str(), usec(start, enc_time), mean_d,
                   usec(enc_time, mean_time), gmi_d, usec(mean_time, gmi_time),
                   ea1c_d, usec(gmi_time, ea1c_time),
                   usec(ea1c_time, dec_time));
        }
    };

    auto start = hrc::now();
    if (!csv)
        printf("Stats for no encryption:\n");
    // testVector(data.bg, "bg");
    testVector(data.cgm, "cgm");
    // testVector(data.cho, "cho");
    // testVector(data.hbgi, "hbgi");
    // testVector(data.insulin, "insulin");
    // testVector(data.lbgi, "lbgi");
    // testVector(data.risk, "risk");
    auto end = hrc::now();
    if (!csv) {
        printf("    total time: %lld us or %f s\n", usec(start, end),
               usec(start, end) / 1e6);
    }
};

void sealSuite(const GlucoseData &data, const int id, const bool csv = true) {
    using std::vector, std::string;
    typedef std::chrono::high_resolution_clock hrc;

    const auto usec = [](decltype(hrc::now()) &start,
                         decltype(hrc::now()) &end) {
        return std::chrono::duration_cast<std::chrono::microseconds>(end -
                                                                     start)
            .count();
    };

    const auto testVector = [&usec, csv, id](const vector<double> &v,
                                             const string &label) {
        auto start = hrc::now();

        SealCalc calc;
        seal::Ciphertext enc = calc.encrypt(v);

        auto enc_time = hrc::now();
        seal::Ciphertext mean = calc.mean(enc, v.size());
        auto mean_time = hrc::now();

        seal::Ciphertext gmi = calc.gmi(mean);
        auto gmi_time = hrc::now();

        seal::Ciphertext ea1c = calc.ea1c(mean);
        auto ea1c_time = hrc::now();

        // no decryption needed
        double mean_d = calc.decrypt(mean, 1)[0];
        double gmi_d = calc.decrypt(gmi, 1)[0];
        double ea1c_d = calc.decrypt(ea1c, 1)[0];
        auto dec_time = hrc::now();

        if (csv) {
            printf("SEAL %s %d, %lld, %f, %lld, %f, %lld, %f, %lld, %lld\n",
                   label.c_str(), id, usec(start, enc_time), mean_d,
                   usec(enc_time, mean_time), gmi_d, usec(mean_time, gmi_time),
                   ea1c_d, usec(gmi_time, ea1c_time),
                   usec(ea1c_time, dec_time));
        } else {

            printf(
                "    %s: enc (%lld us), mean=%f (%lld us), gmi=%f (%lld us), "
                "ea1c=%f (%lld us), dec (%lld us)\n",
                label.c_str(), usec(start, enc_time), mean_d,
                usec(enc_time, mean_time), gmi_d, usec(mean_time, gmi_time),
                ea1c_d, usec(gmi_time, ea1c_time), usec(ea1c_time, dec_time));
        }
    };

    auto start = hrc::now();
    if (!csv)
        printf("Stats for Microsoft SEAL:\n");
    // testVector(data.bg, "bg");
    testVector(data.cgm, "cgm");
    // testVector(data.cho, "cho");
    // testVector(data.hbgi, "hbgi");
    // testVector(data.insulin, "insulin");
    // testVector(data.lbgi, "lbgi");
    // testVector(data.risk, "risk");
    auto end = hrc::now();
    if (!csv) {
        printf("    total time: %lld us or %f s\n", usec(start, end),
               usec(start, end) / 1e6);
    }
}

void heaanSuite(const GlucoseData &data, const int id, const bool csv = true) {
    using std::vector, std::string, std::complex;
    typedef std::chrono::high_resolution_clock hrc;

    const auto usec = [](decltype(hrc::now()) &start,
                         decltype(hrc::now()) &end) {
        return std::chrono::duration_cast<std::chrono::microseconds>(end -
                                                                     start)
            .count();
    };

    const auto toComplexVector = [](const vector<double> &v) {
        vector<complex<double>> res;
        res.reserve(v.size());
        for (double d : v)
            res.emplace_back(d, 0);
        return res;
    };

    const auto testVector = [&usec, csv, id](vector<complex<double>> v,
                                             const string &label) {
        auto start = hrc::now();

        HeaanCalc calc;
        size_t n = v.size();
        Ciphertext enc = calc.encrypt(v);

        auto enc_time = hrc::now();
        Ciphertext mean = calc.mean(enc, n);
        auto mean_time = hrc::now();

        Ciphertext gmi = calc.gmi(mean);
        auto gmi_time = hrc::now();

        Ciphertext ea1c = calc.ea1c(mean);
        auto ea1c_time = hrc::now();

        // no decryption needed
        double mean_d = calc.decrypt(mean, 1)[0].real();
        double gmi_d = calc.decrypt(gmi, 1)[0].real();
        double ea1c_d = calc.decrypt(ea1c, 1)[0].real();
        auto dec_time = hrc::now();

        if (csv) {
            printf("HEAAN %s %d, %lld, %f, %lld, %f, %lld, %f, %lld, %lld\n",
                   label.c_str(), id, usec(start, enc_time), mean_d,
                   usec(enc_time, mean_time), gmi_d, usec(mean_time, gmi_time),
                   ea1c_d, usec(gmi_time, ea1c_time),
                   usec(ea1c_time, dec_time));
        } else {
            printf(
                "    %s: enc (%lld us), mean=%f (%lld us), gmi=%f (%lld us), "
                "ea1c=%f (%lld us), dec (%lld us)\n",
                label.c_str(), usec(start, enc_time), mean_d,
                usec(enc_time, mean_time), gmi_d, usec(mean_time, gmi_time),
                ea1c_d, usec(gmi_time, ea1c_time), usec(ea1c_time, dec_time));
        }
    };

    auto start = hrc::now();
    if (!csv)
        printf("Stats for HEAAN:\n");
    // testVector(toComplexVector(data.bg), "bg");
    testVector(toComplexVector(data.cgm), "cgm");
    // testVector(toComplexVector(data.cho), "cho");
    // testVector(toComplexVector(data.hbgi), "hbgi");
    // testVector(toComplexVector(data.insulin), "insulin");
    // testVector(toComplexVector(data.lbgi), "lbgi");
    // testVector(toComplexVector(data.risk), "risk");
    auto end = hrc::now();
    if (!csv) {
        printf("    total time: %lld us or %f s\n", usec(start, end),
               usec(start, end) / 1e6);
    }
};

void helibSuite(const GlucoseData &data, const int id, const bool csv = true) {
    using std::vector, std::string;
    typedef std::chrono::high_resolution_clock hrc;

    const auto usec = [](decltype(hrc::now()) &start,
                         decltype(hrc::now()) &end) {
        return std::chrono::duration_cast<std::chrono::microseconds>(end -
                                                                     start)
            .count();
    };

    const auto testVector = [&usec, csv, id](const vector<double> &v,
                                             const string &label) {
        using namespace helib;
        auto start = hrc::now();

        HelibCalc calc;
        Ctxt enc = calc.encrypt(v);

        auto enc_time = hrc::now();
        Ctxt mean = calc.mean(enc, v.size());
        auto mean_time = hrc::now();

        Ctxt gmi = calc.gmi(mean);
        auto gmi_time = hrc::now();

        Ctxt ea1c = calc.ea1c(mean);
        auto ea1c_time = hrc::now();

        // no decryption needed
        double mean_d = calc.decrypt(mean, 1)[0];
        double gmi_d = calc.decrypt(gmi, 1)[0];
        double ea1c_d = calc.decrypt(ea1c, 1)[0];
        auto dec_time = hrc::now();

        if (csv) {
            printf("HElib %s %d, %lld, %f, %lld, %f, %lld, %f, %lld, %lld\n",
                   label.c_str(), id, usec(start, enc_time), mean_d,
                   usec(enc_time, mean_time), gmi_d, usec(mean_time, gmi_time),
                   ea1c_d, usec(gmi_time, ea1c_time),
                   usec(ea1c_time, dec_time));
        } else {
            printf(
                "    %s: enc (%lld us), mean=%f (%lld us), gmi=%f (%lld us), "
                "ea1c=%f (%lld us), dec (%lld us)\n",
                label.c_str(), usec(start, enc_time), mean_d,
                usec(enc_time, mean_time), gmi_d, usec(mean_time, gmi_time),
                ea1c_d, usec(gmi_time, ea1c_time), usec(ea1c_time, dec_time));
        }
    };

    auto start = hrc::now();
    if (!csv)
        printf("Stats for HElib:\n");
    // testVector(data.bg, "bg");
    testVector(data.cgm, "cgm");
    // testVector(data.cho, "cho");
    // testVector(data.hbgi, "hbgi");
    // testVector(data.insulin, "insulin");
    // testVector(data.lbgi, "lbgi");
    // testVector(data.risk, "risk");
    auto end = hrc::now();
    if (!csv) {
        printf("    total time: %lld us or %f s\n", usec(start, end),
               usec(start, end) / 1e6);
    }
}

int main(int argc, char **argv) {
    const bool csv = true;
    if (csv) {
        printf("Label, encryption time, mean, mean time, gmi, gmi time, ea1c, "
               "ea1c time, decryption time\n");
    }

    for (int i = 61; i <= 100; ++i) {
        string filename = "all1day/adult" + to_string(i) + ".csv";
        GlucoseData data = readCsv(filename);

        unencryptedSuite(data, i, csv);
        sealSuite(data, i, csv);
        heaanSuite(data, i, csv);
        helibSuite(data, i, csv);
        fflush(stdout);
        fprintf(stderr, "%s %d\n", filename.c_str(), i);
    }
}