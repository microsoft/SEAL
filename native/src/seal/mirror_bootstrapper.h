#pragma once

#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/batchencoder.h"
#include "seal/ciphertext.h"
#include "seal/plaintext.h"
#include <vector>
#include <functional>
#include <chrono>

namespace seal {

class MirrorBootstrapper {
public:
    struct Config {
        double target_noise;
        int max_iterations;
    };

    struct Stats {
        int iterations = 0;
        double initial_noise = 0;
        double final_noise = 0;
        double time_ms = 0;
        bool converged = false;
    };

    MirrorBootstrapper(const SEALContext &context,
                       Decryptor &decryptor,
                       Encryptor &encryptor,
                       BatchEncoder &encoder,
                       const Config &config);

    bool bootstrap(Ciphertext &encrypted, Stats *stats = nullptr) const;
    int noise_budget(const Ciphertext &encrypted) const;

    static Config default_config() {
        return {40.0, 100};
    }

private:
    const SEALContext &context_;
    Decryptor &decryptor_;
    Encryptor &encryptor_;
    BatchEncoder &encoder_;
    Config config_;
};

} // namespace seal
