#ifndef dnp3sav6_details_randomnumbergenerator_hpp
#define dnp3sav6_details_randomnumbergenerator_hpp

#include "irandomnumbergenerator.hpp"

namespace DNP3SAv6 { namespace Details {
class RandomNumberGenerator : public IRandomNumberGenerator
{
public :
	RandomNumberGenerator() = default;
	virtual ~RandomNumberGenerator() = default;

	RandomNumberGenerator(RandomNumberGenerator const&) = delete;
	RandomNumberGenerator& operator=(RandomNumberGenerator const&) = delete;
	RandomNumberGenerator(RandomNumberGenerator&&) = default;
	RandomNumberGenerator& operator=(RandomNumberGenerator&&) = default;

	virtual void generate(boost::asio::mutable_buffer &buffer) override;
};
}}

#endif


