/* Copyright 2019  Ronald Landheer-Cieslak
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
#include "aes256cbcencryption.hpp"
#include "../exceptions/contract.hpp"
#include "../exceptions.hpp"
#include <algorithm>
#include <openssl/aes.h>
#include <openssl/crypto.h>

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 { namespace Details { 
/*virtual */void AES256CBCEncryption::setIV(const_buffer const &iv)
{
    pre_condition(iv.size() == sizeof(initialization_vector_));
    memcpy(initialization_vector_, iv.data(), iv.size());
}
/*virtual */const_buffer AES256CBCEncryption::getIV() const
{
    return const_buffer(initialization_vector_, sizeof(initialization_vector_));
}
/*virtual */mutable_buffer AES256CBCEncryption::encrypt(mutable_buffer const &out, const_buffer const &key, const_buffer const &cleartext)
{
    pre_condition(cleartext.size() < std::numeric_limits< decltype(work_buffer_.first_chunk_.size_) >::max());
    pre_condition(out.size() >= (((cleartext.size() + 2/* for the header */) + 15) % 16));
    static_assert(sizeof(decltype(WorkBuffer::FirstChunk::size_)) == 2, "Unexpected cleartext header size - revise pre-condition above");

    /* we stick a header at the start of the data to indicate how much data there is, so the first chunk of actual data we'll include is smaller than the subsequent chunks. */
    work_buffer_.first_chunk_.size_ = static_cast< decltype(work_buffer_.first_chunk_.size_) >(cleartext.size());
    unsigned char const *cleartext_curr(static_cast< unsigned char const* >(cleartext.data()));
    unsigned char const *const cleartext_end(cleartext_curr + cleartext.size());
    unsigned char *const ciphertext_begin(static_cast< unsigned char* >(out.data()));
    unsigned char *ciphertext_curr(ciphertext_begin);
    unsigned char *const ciphertext_end(ciphertext_curr + out.size());
    bool first(true);
    while (cleartext_curr != cleartext_end)
    {
        unsigned int remaining;
        if (first)
        {
            remaining = sizeof(work_buffer_.first_chunk_.data_);
            size_t size_to_copy(min< size_t >(sizeof(work_buffer_.first_chunk_.data_), distance(cleartext_curr, cleartext_end)));
            copy(cleartext_curr, cleartext_curr + size_to_copy, work_buffer_.first_chunk_.data_);
            cleartext_curr += size_to_copy;
            remaining -= size_to_copy;
            first = false;
        }
        else
        {
            remaining = sizeof(work_buffer_.subsequent_chunks_.data_);
            size_t size_to_copy(min< size_t >(sizeof(work_buffer_.subsequent_chunks_.data_), distance(cleartext_curr, cleartext_end)));
            copy(cleartext_curr, cleartext_curr + size_to_copy, work_buffer_.subsequent_chunks_.data_);
            cleartext_curr += size_to_copy;
            remaining -= size_to_copy;
        }
        /* At the 2019 F2F discussion on adding encryption to the protocol, Herb mentioned we should pad using PKCS#7 padding. 
         * While that is not strictly necessary because we use a lot of other measures already (e.g. we have an IV, we include 
         * the size in the encrypted cleartext, etc.) it doesn't hurt and it does prevent us from leaving a number of bytes 
         * undefined at the end of the ciphertext block. So, after careful consideration, we now pad. */
        if (remaining)
        {
            unsigned char *curr_padding_out(work_buffer_.data_ + (sizeof(work_buffer_.data_) - remaining));
            unsigned char *const out_padding_end(work_buffer_.data_ + sizeof(work_buffer_.data_));
            unsigned char const padding_byte(static_cast< unsigned char >(remaining));
            while (curr_padding_out != out_padding_end)
            {
                *curr_padding_out++ = padding_byte;
            }
        }
        else
        { /* no padding needed */ }

        encryptWorkBuffer(key);

        invariant(distance(ciphertext_curr, ciphertext_end) >= sizeof(work_buffer_.data_));
        ciphertext_curr = copy(begin(work_buffer_.data_), end(work_buffer_.data_), ciphertext_curr);
        invariant(ciphertext_curr <= ciphertext_end);
    }

    return mutable_buffer(ciphertext_begin, distance(ciphertext_begin, ciphertext_curr));
}
/*virtual */mutable_buffer AES256CBCEncryption::decrypt(mutable_buffer const &out, const_buffer const &key, const_buffer const &ciphertext)
{
    if (ciphertext.size() % 16 != 0)
    {
        //TODO statistics, logs, etc.
        return mutable_buffer();
    }
    else
    { /* may be valid input data */ }

    /* The largest possible cleartext size for a given ciphertext is the ciphertext size minus two bytes,
     * assuming no padding at all and therefore just removing the header. */
    size_t const maximum_possible_cleartext_size(ciphertext.size() - 2);
    pre_condition(out.size() >= maximum_possible_cleartext_size);

    unsigned char const *const ciphertext_begin(static_cast< unsigned char const * >(ciphertext.data()));
    unsigned char const *ciphertext_curr(ciphertext_begin);
    unsigned char const *const ciphertext_end(ciphertext_begin + ciphertext.size());
    unsigned char *const cleartext_begin(static_cast< unsigned char * >(out.data()));
    unsigned char *cleartext_curr(cleartext_begin);
    unsigned char *const cleartext_end(cleartext_begin + out.size());

    unsigned int remaining;
    unsigned int expected_padding;
    bool first(true);
    while (ciphertext_curr != ciphertext_end)
    {
        { // copy into the work buffer
            invariant((distance(ciphertext_curr, ciphertext_end) % sizeof(work_buffer_.data_)) == 0);
            invariant(distance(ciphertext_curr, ciphertext_end) >= sizeof(work_buffer_.data_));
            size_t size_to_copy(sizeof(work_buffer_.data_));
            copy(ciphertext_curr, ciphertext_curr + size_to_copy, work_buffer_.data_);
            ciphertext_curr += size_to_copy;
        }
        decryptWorkBuffer(key);
        if (first)
        {
            if (work_buffer_.first_chunk_.size_ > maximum_possible_cleartext_size)
            {
                //TODO statistics, logs, etc.
                return mutable_buffer();
            }
            else
            { /* no-op */ }
            if (work_buffer_.first_chunk_.size_ > out.size())
            {
                //TODO statistics, logs, etc.
                return mutable_buffer();
            }
            else
            { /* no-op */ }
            expected_padding = 16 - ((work_buffer_.first_chunk_.size_ + 2/* header size */) % 16);
            remaining = work_buffer_.first_chunk_.size_;
            invariant(distance(cleartext_curr, cleartext_end) >= 0);
            invariant(static_cast< decltype(remaining) >(distance(cleartext_curr, cleartext_end)) >= remaining);
            size_t const size_to_copy(min< size_t >(remaining, sizeof(work_buffer_.first_chunk_.data_)));
            copy(work_buffer_.first_chunk_.data_, work_buffer_.first_chunk_.data_ + size_to_copy, cleartext_curr);
            cleartext_curr += size_to_copy;
            remaining -= size_to_copy;
            if (!remaining)
            {
                if (!checkPadding(const_buffer(work_buffer_.first_chunk_.data_ + size_to_copy, sizeof(work_buffer_.first_chunk_.data_) - size_to_copy), expected_padding))
                {
                    //TODO statistics, logs, etc.
                    return mutable_buffer();
                }
                else
                { /* padding is OK */ }
            }
            else
            { /* no need to check padding yet - we still have data */ }
            first = false;
        }
        else
        {
            invariant(distance(cleartext_curr, cleartext_end) >= 0);
            invariant(static_cast< decltype(remaining) >(distance(cleartext_curr, cleartext_end)) >= remaining);
            size_t const size_to_copy(min< size_t >(remaining, sizeof(work_buffer_.subsequent_chunks_.data_)));
            copy(work_buffer_.subsequent_chunks_.data_, work_buffer_.subsequent_chunks_.data_ + size_to_copy, cleartext_curr);
            cleartext_curr += size_to_copy;
            remaining -= size_to_copy;
            if (!remaining)
            {
                if (!checkPadding(const_buffer(work_buffer_.subsequent_chunks_.data_ + size_to_copy, sizeof(work_buffer_.subsequent_chunks_.data_) - size_to_copy), expected_padding))
                {
                    //TODO statistics, logs, etc.
                    return mutable_buffer();
                }
                else
                { /* padding is OK */ }
            }
            else
            { /* no need to check padding yet - we still have data */ }
        }
    }

    return mutable_buffer(cleartext_begin, distance(cleartext_begin, cleartext_curr));
}
void AES256CBCEncryption::encryptWorkBuffer(const_buffer const &key)
{
    pre_condition(key.size() == 32);
	AES_KEY aes_key;
	if (0 != AES_set_encrypt_key(static_cast< unsigned char const* >(key.data()), 8 * key.size(), &aes_key))
	{
		throw EncryptionFailure("failed to set encrypt key");
	}
	else
	{ /* everything OK */ }
    // we do CBC encryption, so we XOR the input buffer with the IV before we encrypt it, and the ciphertext becomes the IV for the next round
    static_assert(sizeof(work_buffer_.data_) == sizeof(initialization_vector_), "Unexpected mismatch between the IV size and the work buffer size");
    for (unsigned int i(0); i < sizeof(work_buffer_.data_); ++i)
    {
        work_buffer_.data_[i] ^= initialization_vector_[i];
    }
	AES_encrypt(work_buffer_.data_, work_buffer_.data_, &aes_key);
    copy(begin(work_buffer_.data_), end(work_buffer_.data_), begin(initialization_vector_));
}

void AES256CBCEncryption::decryptWorkBuffer(const_buffer const &key)
{
    pre_condition(key.size() == 32);
	AES_KEY aes_key;
	if (0 != AES_set_decrypt_key(static_cast< unsigned char const* >(key.data()), 8 * key.size(), &aes_key))
	{
		throw EncryptionFailure("failed to set encrypt key");
	}
	else
	{ /* everything OK */ }
    // we do CBC encryption, so we XOR the work buffer with the IV after we decrypt it, but we need to keep the previous ciphertext around because that will be our next IV
    static_assert(sizeof(work_buffer_.data_) == sizeof(initialization_vector_), "Unexpected mismatch between the IV size and the work buffer size");
    unsigned char next_initialization_vector[sizeof(initialization_vector_)];
    copy(begin(work_buffer_.data_), end(work_buffer_.data_), begin(next_initialization_vector));

	AES_decrypt(work_buffer_.data_, work_buffer_.data_, &aes_key);
    for (unsigned int i(0); i < sizeof(work_buffer_.data_); ++i)
    {
        work_buffer_.data_[i] ^= initialization_vector_[i];
    }
    copy(begin(next_initialization_vector), end(next_initialization_vector), begin(initialization_vector_));
}
bool AES256CBCEncryption::checkPadding(boost::asio::const_buffer const& padding_data, unsigned char expected_padding) const
{
    if (padding_data.size() != expected_padding) return false;
    unsigned char const *const padding_data_begin(static_cast< unsigned char const * >(padding_data.data()));
    unsigned char const *const padding_data_end(padding_data_begin + padding_data.size());
    for (unsigned char const *padding_data_curr(padding_data_begin); padding_data_curr != padding_data_end; ++padding_data_curr)
    {
        if (*padding_data_curr != expected_padding) return false;
    }
    return true;
}
}}


