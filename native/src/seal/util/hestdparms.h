// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once 

/**
Largest allowed bit counts for coeff_modulus based on the security estimates from 
HomomorphicEncryption.org security standard. Microsoft SEAL always samples the secret key 
from a ternary {-1, 0, 1} distribution. These tables are used to enforce a minimum 
security level when constructing a SEALContext. SEAL_HE_STD_PARMS_128_TC (below) 
is used for this purpose by default, but this can easily be changed by editing 
seal/util/globals.h if, e.g., higher than 128-bit or post-quantum security levels 
should be enforced.
*/
// Ternary secret; 128 bits classical security
#define SEAL_HE_STD_PARMS_128_TC                \
    { std::size_t(1024),    27     },           \
    { std::size_t(2048),    54     },           \
    { std::size_t(4096),    109    },           \
    { std::size_t(8192),    218    },           \
    { std::size_t(16384),   438    },           \
    { std::size_t(32768),   881    }

// Ternary secret; 192 bits classical security
#define SEAL_HE_STD_PARMS_192_TC                \
    { std::size_t(1024),    19     },           \
    { std::size_t(2048),    37     },           \
    { std::size_t(4096),    75     },           \
    { std::size_t(8192),    152    },           \
    { std::size_t(16384),   305    },           \
    { std::size_t(32768),   611    }

// Ternary secret; 256 bits classical security
#define SEAL_HE_STD_PARMS_256_TC                \
    { std::size_t(1024),    14     },           \
    { std::size_t(2048),    29     },           \
    { std::size_t(4096),    58     },           \
    { std::size_t(8192),    118    },           \
    { std::size_t(16384),   237    },           \
    { std::size_t(32768),   476    }

// Ternary secret; 128 bits quantum security
#define SEAL_HE_STD_PARMS_128_TQ                \
    { std::size_t(1024),    25     },           \
    { std::size_t(2048),    51     },           \
    { std::size_t(4096),    101    },           \
    { std::size_t(8192),    202    },           \
    { std::size_t(16384),   411    },           \
    { std::size_t(32768),   827    }

// Ternary secret; 192 bits quantum security
#define SEAL_HE_STD_PARMS_192_TQ                \
    { std::size_t(1024),    17     },           \
    { std::size_t(2048),    35     },           \
    { std::size_t(4096),    70     },           \
    { std::size_t(8192),    141    },           \
    { std::size_t(16384),   284    },           \
    { std::size_t(32768),   571    }

// Ternary secret; 256 bits quantum security
#define SEAL_HE_STD_PARMS_256_TQ                \
    { std::size_t(1024),    13     },           \
    { std::size_t(2048),    27     },           \
    { std::size_t(4096),    54     },           \
    { std::size_t(8192),    109    },           \
    { std::size_t(16384),   220    },           \
    { std::size_t(32768),   443    }

// Standard deviation for error distribution
#define SEAL_HE_STD_PARMS_ERROR_STD_DEV 3.20
