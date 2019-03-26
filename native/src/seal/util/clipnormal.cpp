// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdexcept>
#include "seal/util/clipnormal.h"

using namespace std;

namespace seal
{
    namespace util
    {
        ClippedNormalDistribution::ClippedNormalDistribution(
            result_type mean,
            result_type standard_deviation,
            result_type max_deviation) :
            normal_(mean, standard_deviation),
            max_deviation_(max_deviation)
        {
            // Verify arguments.
            if (standard_deviation < 0)
            {
                throw invalid_argument("standard_deviation");
            }
            if (max_deviation < 0)
            {
                throw invalid_argument("max_deviation");
            }
        }
    }
}
