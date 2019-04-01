// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/randomgen.h"

using namespace std;

namespace seal
{
    /**
    Returns the default random number generator factory. This instance should
    not be destroyed.
    */
    auto UniformRandomGeneratorFactory::default_factory()
        -> const shared_ptr<UniformRandomGeneratorFactory>
    {
        static const shared_ptr<UniformRandomGeneratorFactory>
            default_factory{ new SEAL_DEFAULT_RNG_FACTORY };
        return default_factory;
    }
#ifdef SEAL_USE_AES_NI_PRNG
    auto FastPRNGFactory::create() -> shared_ptr<UniformRandomGenerator>
    {
        if (!(seed_[0] | seed_[1]))
        {
            return make_shared<FastPRNG>(random_uint64(), random_uint64());
        }
        else
        {
            return make_shared<FastPRNG>(seed_[0], seed_[1]);
        }
    }
#endif
}
