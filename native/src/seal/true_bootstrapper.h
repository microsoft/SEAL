#pragma once

#include "seal/context.h"
#include "seal/evaluator.h"
#include "seal/encryptor.h"
#include "seal/batchencoder.h"
#include "seal/keygenerator.h"
#include "seal/ciphertext.h"
#include "seal/plaintext.h"
#include "seal/secretkey.h"
#include "seal/publickey.h"
#include <vector>
#include <chrono>

namespace seal {

class TrueBootstrapper {
public:
    struct Config {
        int cycles = 1;
        Config() : cycles(1) {}
    };

    struct Stats {
        double initial_noise = 0;
        double final_noise = 0;
        double time_ms = 0;
        int cycles = 0;
        bool homomorphic = true;
        bool value_preserved = false;
    };

    struct BootstrapKeys {
        Ciphertext enc_zero;
    };

    TrueBootstrapper(const SEALContext &context,
                     const BootstrapKeys &keys,
                     const Config &config = Config());

    bool bootstrap(Ciphertext &encrypted, Stats *stats = nullptr);

    static BootstrapKeys generate_keys(const SEALContext &context,
                                        const SecretKey &sk);

private:
    const SEALContext &context_;
    BootstrapKeys keys_;
    Config config_;
};

} // namespace seal
