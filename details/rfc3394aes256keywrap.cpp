#include "rfc3394aes256keywrap.hpp" 
#include "../exceptions/contract.hpp"
#include "../exceptions.hpp"
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <memory>

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 { namespace Details {
/*static */unsigned char const RFC3394AES256KeyWrap::default_iv__[8] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };

RFC3394AES256KeyWrap::RFC3394AES256KeyWrap()
{ /* no-op */ }
/*virtual */RFC3394AES256KeyWrap::~RFC3394AES256KeyWrap()
{ /* no-op */ }

/*virtual */void RFC3394AES256KeyWrap::wrap(
      mutable_buffer &out_buffer
    , const_buffer const &key_encrypting_key
    , const_buffer const &key_data
    ) const/* override*/
{
	pre_condition(key_encrypting_key.size() == (256 / 8));
	pre_condition(key_data.size() < 0x7FFFFFFF);
	pre_condition(key_data.size() >= 16);
	pre_condition(key_data.size() % 8 == 0);
	pre_condition(out_buffer.size() >= key_data.size() + 8);

	AES_KEY key;
	if (0 != AES_set_encrypt_key(static_cast< unsigned char const* >(key_encrypting_key.data()), 8 * key_encrypting_key.size(), &key))
	{
		throw RFC3394AES256KeyWrapFailure("failed to set encrypt key");
	}
	else
	{ /* everything OK */ }

	unsigned char work_buffer[16];

	unsigned char *const beg_out(static_cast< unsigned char* >(out_buffer.data()));
	unsigned char *const end_out(beg_out + out_buffer.size());

	memmove(beg_out + 8, key_data.data(), key_data.size());
	memcpy(work_buffer, default_iv__, 8);

	uint64_t t(1);
	for (unsigned int round = 0; round < 6; round++)
	{
		unsigned char *curr_out = beg_out + 8;
		while (curr_out < end_out)
		{
			memcpy(work_buffer + 8, curr_out, 8);
			AES_encrypt(work_buffer, work_buffer, &key);
			work_buffer[7] ^= (unsigned char)(t & 0xff);
			work_buffer[6] ^= (unsigned char)((t >> 8) & 0xff);
			work_buffer[5] ^= (unsigned char)((t >> 16) & 0xff);
			work_buffer[4] ^= (unsigned char)((t >> 24) & 0xff);
			work_buffer[3] ^= (unsigned char)((t >> 32) & 0xff);
			work_buffer[2] ^= (unsigned char)((t >> 40) & 0xff);
			work_buffer[1] ^= (unsigned char)((t >> 48) & 0xff);
			work_buffer[0] ^= (unsigned char)((t >> 56) & 0xff);
			memcpy(curr_out, work_buffer + 8, 8);
			curr_out += 8;
			++t;
		}
	}
	memcpy(beg_out, work_buffer, 8);

	out_buffer = mutable_buffer(out_buffer.data(), key_data.size() + 8);
}
/*virtual */bool RFC3394AES256KeyWrap::unwrap(mutable_buffer &out_buffer, const_buffer const &key_encrypting_key, const_buffer const &key_data) const/* override*/
{
	pre_condition(key_encrypting_key.size() == (256 / 8));
	pre_condition(key_data.size() < 0x7FFFFFFF);
	pre_condition(key_data.size() >= 16);
	pre_condition(key_data.size() % 8 == 0);
	pre_condition(out_buffer.size() == key_data.size() - 8);

	AES_KEY key;
	if (1 != AES_set_decrypt_key(static_cast< unsigned char const* >(key_encrypting_key.data()), 8 * key_encrypting_key.size(), &key))
	{
		throw RFC3394AES256KeyWrapFailure("failed to set decrypt key");
	}
	else
	{ /* all is well */ }

	unsigned char *beg_out(static_cast< unsigned char* >(out_buffer.data()));
	unsigned char *const end_out(beg_out + out_buffer.size());

	const unsigned char *in(static_cast< unsigned char const* >(key_data.data()));
	size_t inlen(key_data.size());

	unsigned char iv[8];
	unsigned char work_buffer[16];
	unsigned char *curr_out(beg_out);
	uint64_t t;
	inlen -= 8;
	t = 6 * (inlen >> 3);
	memcpy(work_buffer, in, 8);
	memmove(beg_out, in + 8, inlen);
	for (unsigned int round = 0; round < 6; round++)
	{
		curr_out = end_out;
		do
		{
			curr_out -= 8;
			work_buffer[7] ^= (unsigned char)(t & 0xff);
			work_buffer[6] ^= (unsigned char)((t >> 8) & 0xff);
			work_buffer[5] ^= (unsigned char)((t >> 16) & 0xff);
			work_buffer[4] ^= (unsigned char)((t >> 24) & 0xff);
			work_buffer[3] ^= (unsigned char)((t >> 32) & 0xff);
			work_buffer[2] ^= (unsigned char)((t >> 40) & 0xff);
			work_buffer[1] ^= (unsigned char)((t >> 48) & 0xff);
			work_buffer[0] ^= (unsigned char)((t >> 56) & 0xff);
			memcpy(work_buffer + 8, curr_out, 8);
			AES_decrypt(work_buffer, work_buffer, &key);
			memcpy(curr_out, work_buffer + 8, 8);
			--t;
		}
		while (curr_out > beg_out);
	}
	memcpy(iv, work_buffer, 8);

	return CRYPTO_memcmp(iv, default_iv__, sizeof(default_iv__)) == 0;
}
}}

