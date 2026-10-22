#include "crypto/Random.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <mutex>
#include <stdexcept>

namespace cryptowl::crypto {

namespace {

class Rng
{
public:
    Rng()
    {
        mbedtls_ctr_drbg_init(&m_ctrDrbg);
        mbedtls_entropy_init(&m_entropy);

        static constexpr char kPersonalization[] = "cryptowl-desktop";
        const int rc = mbedtls_ctr_drbg_seed(
            &m_ctrDrbg, mbedtls_entropy_func, &m_entropy,
            reinterpret_cast<const unsigned char *>(kPersonalization),
            sizeof(kPersonalization) - 1);
        if (rc != 0) {
            mbedtls_ctr_drbg_free(&m_ctrDrbg);
            mbedtls_entropy_free(&m_entropy);
            throw std::runtime_error("failed to seed the CSPRNG");
        }
    }

    int random(unsigned char *output, std::size_t length)
    {
        return mbedtls_ctr_drbg_random(&m_ctrDrbg, output, length);
    }

private:
    mbedtls_ctr_drbg_context m_ctrDrbg{};
    mbedtls_entropy_context m_entropy{};
};

Rng &rng()
{
    static Rng instance;
    return instance;
}

std::mutex &rngMutex()
{
    static std::mutex mutex;
    return mutex;
}

}

Bytes randomBytes(std::size_t count)
{
    Bytes out(count);
    if (count == 0)
        return out;

    const std::lock_guard<std::mutex> lock(rngMutex());
    if (rng().random(out.data(), out.size()) != 0)
        throw std::runtime_error("CSPRNG failure");
    return out;
}

}
