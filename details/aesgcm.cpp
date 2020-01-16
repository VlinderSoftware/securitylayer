/* Copyright 2020  Ronald Landheer-Cieslak
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. */
#include "aesgcm.hpp"
#include <algorithm>
#include "../exceptions/contract.hpp"
#include "../exceptions.hpp"
#include "../aeadalgorithm.hpp"

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 { namespace Details { 
AESGCM::AESGCM(
      mutable_buffer const &out
    , const_buffer const &key
    , const_buffer const &nonce
    , const_buffer const &associated_data
    , size_t authentication_tag_size
    )
    : key_(key)
    , associated_data_(associated_data)
    , out_(out)
    , out_begin_(static_cast< unsigned char* >(out_.data()))
    , out_curr_(out_begin_)
    , out_end_(out_begin_ + out_.size())
    , tag_buffer_adapter_(mutable_buffer(potential_tag_, sizeof(potential_tag_)))
{
    pre_condition(authentication_tag_size == 16);
    auto context_deleter([=](EVP_CIPHER_CTX *context){ EVP_CIPHER_CTX_free(context); });
    unique_ptr< EVP_CIPHER_CTX, decltype(context_deleter) > context(EVP_CIPHER_CTX_new(), context_deleter);
    context_ = context.get();
    if (!context_) throw std::bad_alloc();

    pre_condition(key.data());
    pre_condition(key.size() == getKeySize());

    // zero-pad the IV
    static_assert(sizeof(iv_) == AESGCM::getIVSize(), "Wrong IV size");
    memset(iv_, 0, sizeof(iv_)); // just making it explicit
    memcpy(iv_, nonce.data(), min(nonce.size(), sizeof(iv_)));

    context.release();
}

/*virtual */AESGCM::~AESGCM()
{
    EVP_CIPHER_CTX_free(context_);
}

/*virtual */void AESGCM::encrypt(const_buffer const &plaintext)/* override*/
{
    if (state_ == undetermined__)
    {
        if (1 != EVP_EncryptInit_ex(context_, EVP_aes_256_gcm(), NULL, static_cast< unsigned char const* >(key_.data()), iv_))
        {
            throw FailedToInitializeAEASGCM("EVP_EncryptInit_ex failed");
        }
        else
        { /* all is well */ }
        int len; // ignored, but appears to be needed by OpenSSL
        if (1 != EVP_EncryptUpdate(context_, NULL, &len, static_cast< unsigned char const* >(associated_data_.data()), associated_data_.size()))
        {
            throw AESGCMEncryptionFailed("Failed to add associated data");
        }
        else
        { /* all is well */ }
        state_ = encrypting__;
    }
    else
    { /* no-op */ }
    if (state_ != encrypting__) state_ = error__;

    // GCM is a stream cipher, so the output needs to have enough space for the plaintext consumed so far, the plaintext being added here, and the size of the tag.
    size_t const size_of_output_buffer(distance(out_begin_, out_end_));
    size_t const total_plaintext_size(plaintext.size() + consumed_input_);
    if (size_of_output_buffer < (total_plaintext_size + getAEADAlgorithmAuthenticationTagSize(AEADAlgorithm::aes256_gcm__))) state_ = error__;

    if (state_ == error__) return;

    // if we get here, all preconditions are met.
    int len;
    if (1 != EVP_EncryptUpdate(context_, out_curr_, &len, static_cast< unsigned char const* >(plaintext.data()), plaintext.size()))
    {
        throw AESGCMEncryptionFailed("Failed to encrypt plaintext data");
    }
    else
    { /* all is well */ }
    out_curr_ += len;
}

/*virtual */const_buffer AESGCM::getEncrypted()/* override*/
{
    if (state_ == error__) return const_buffer();

    size_t const size_of_output_buffer(distance(out_begin_, out_end_));
    size_t const total_plaintext_size(consumed_input_);
    invariant(size_of_output_buffer >= (total_plaintext_size + getAEADAlgorithmAuthenticationTagSize(AEADAlgorithm::aes256_gcm__)));
    invariant(16 == getAEADAlgorithmAuthenticationTagSize(AEADAlgorithm::aes256_gcm__));

    int len;
    if (1 != EVP_EncryptFinal_ex(context_, out_curr_, &len))
    {
        throw AESGCMEncryptionFailed("Failed to finalize encryption");
    }
    else
    { /* all is well */ }
    out_curr_ += len;

    if (1 != EVP_CIPHER_CTX_ctrl(context_, EVP_CTRL_GCM_GET_TAG, getAEADAlgorithmAuthenticationTagSize(AEADAlgorithm::aes256_gcm__), out_curr_))
    {
        throw AESGCMEncryptionFailed("Failed to retrieve authentication tag");
    }
    else
    { /* all is well */ }
    out_curr_ += 16;

    return const_buffer(out_begin_, distance(out_begin_, out_curr_));
}

/*virtual */void AESGCM::decrypt(const_buffer const &ciphertext)/* override*/
{
    if (state_ == undetermined__)
    {
        if (1 != EVP_DecryptInit_ex(context_, EVP_aes_256_gcm(), NULL, static_cast< unsigned char const* >(key_.data()), iv_))
        {
            throw FailedToInitializeAEASGCM("EVP_EncryptInit_ex failed");
        }
        else
        { /* all is well */ }
        int len; // ignored, but appears to be needed by OpenSSL
        if (1 != EVP_DecryptUpdate(context_, NULL, &len, static_cast< unsigned char const* >(associated_data_.data()), associated_data_.size()))
        {
            throw AESGCMDecryptionFailed("Failed to add associated data");
        }
        else
        { /* all is well */ }
        state_ = decrypting__;
    }
    else
    { /* no-op */ }
    if (state_ != decrypting__) state_ = error__;

    // GCM is a stream cipher, so the output needs to have enough space for the plaintext consumed so far, the plaintext being added here, and the size of the tag.
    size_t const size_of_output_buffer(distance(out_begin_, out_end_));
    size_t const total_ciphertext_size(ciphertext.size() + consumed_input_);
    if (size_of_output_buffer < (total_ciphertext_size - getAEADAlgorithmAuthenticationTagSize(AEADAlgorithm::aes256_gcm__))) state_ = error__;

    if (state_ == error__) return;

    // if we get here, all preconditions are met.

    // We keep the latest 16 bytes, where 16 is the size of the tag, in a buffer and run the rest though the 
    // cipher in FIFO order. That way, we can check the tag (which will be in the buffer) against the digest. 
    unsigned char buffer[16];
    unsigned char const *ciphertext_curr(static_cast< unsigned char const * >(ciphertext.data()));
    unsigned char const *const ciphertext_end(ciphertext_curr + ciphertext.size());
    while (ciphertext_curr != ciphertext_end)
    {
        size_t remaining(std::distance(ciphertext_curr, ciphertext_end));
        auto push_result(tag_buffer_adapter_.push(mutable_buffer(buffer, sizeof(buffer)), const_buffer(ciphertext_curr, remaining)));
        size_t const throughput_produced(push_result.first);
        size_t const input_consumed(push_result.second);
        assert((ciphertext_curr + input_consumed) <= ciphertext_end);
        ciphertext_curr += input_consumed;

        int len;
        if (1 != EVP_DecryptUpdate(context_, out_curr_, &len, buffer, throughput_produced))
        {
            throw AESGCMDecryptionFailed("Failed to decrypt plaintext data");
        }
        else
        { /* all is well */ }
        out_curr_ += len;
    }
}

/*virtual */const_buffer AESGCM::getDecrypted()/* override*/
{
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(context_, EVP_CTRL_GCM_SET_TAG, 16, potential_tag_))
    {
        throw AESGCMDecryptionFailed("Failed to set expected tag");
    }
    else
    { /* all is well */ }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    int len;
    int ret(EVP_DecryptFinal_ex(context_, out_curr_, &len));
    out_curr_ += len;

    if (ret > 0)
    {
        return const_buffer(out_begin_, distance(out_begin_, out_curr_));
    }
    else
    {
        return const_buffer();
    }
}
}}


