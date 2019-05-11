// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_CHACHA_POLY_AEAD_OPENSSH_H
#define BITCOIN_CRYPTO_CHACHA_POLY_AEAD_OPENSSH_H

#include <crypto/chacha20.h>

#include <cmath>

/* A AEAD class for ChaCha20-Poly1305@openssh. */
class ChaCha20Poly1305OpenSSHAEAD
{
private:
    ChaCha20 m_chacha_main;                                      // payload and poly1305 key-derivation cipher instance
    ChaCha20 m_chacha_header;                                    // AAD cipher instance (encrypted length)
    unsigned char m_aad_keystream_buffer[64]; // aad keystream cache
    uint64_t m_cached_aad_seqnr;                                 // aad keystream cache hint

public:
    ChaCha20Poly1305OpenSSHAEAD(const unsigned char* K_1, size_t K_1_len, const unsigned char* K_2, size_t K_2_len);

    bool Crypt(uint64_t seqnr_payload, uint64_t seqnr_aad, int aad_pos, unsigned char* dest, size_t dest_len, const unsigned char* src, size_t src_len, bool is_encrypt);

    /** decrypts the 3 bytes AAD data and decodes it into a uint32_t field */
    bool GetLength(uint32_t* len24_out, uint64_t seqnr_aad, int aad_pos, const uint8_t* ciphertext);
};

#endif // BITCOIN_CRYPTO_CHACHA_POLY_AEAD_OPENSSH_H
