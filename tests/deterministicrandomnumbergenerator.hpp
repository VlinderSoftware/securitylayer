#ifndef dnp3sav6_tests_deterministicrandomnumbergenerator_hpp
#define dnp3sav6_tests_deterministicrandomnumbergenerator_hpp

#include "../details/irandomnumbergenerator.hpp"
#include <openssl/aes.h>

namespace DNP3SAv6 { namespace Tests {
class DeterministicRandomNumberGenerator : public Details::IRandomNumberGenerator
{
public :
	DeterministicRandomNumberGenerator();
	DeterministicRandomNumberGenerator(boost::asio::const_buffer const &seed);
	virtual ~DeterministicRandomNumberGenerator() = default;

	DeterministicRandomNumberGenerator(DeterministicRandomNumberGenerator const&) = delete;
	DeterministicRandomNumberGenerator& operator=(DeterministicRandomNumberGenerator const&) = delete;
	DeterministicRandomNumberGenerator(DeterministicRandomNumberGenerator&&) = default;
	DeterministicRandomNumberGenerator& operator=(DeterministicRandomNumberGenerator&&) = default;

	void setSeed(boost::asio::const_buffer const &seed);
	virtual void generate(boost::asio::mutable_buffer &buffer) override;

private :
	AES_KEY key_;
	unsigned char buffer_[16];
	unsigned int avail_;
};
}}

#endif


