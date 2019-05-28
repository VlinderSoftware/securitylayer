#ifndef dnp3sav6_details_irandomnumbergenerator_hpp
#define dnp3sav6_details_irandomnumbergenerator_hpp

#include <boost/asio.hpp>

namespace DNP3SAv6 { namespace Details {
class IRandomNumberGenerator
{
public :
	IRandomNumberGenerator() = default;
	virtual ~IRandomNumberGenerator() = default;

	IRandomNumberGenerator(IRandomNumberGenerator const&) = delete;
	IRandomNumberGenerator& operator=(IRandomNumberGenerator const&) = delete;
	IRandomNumberGenerator(IRandomNumberGenerator&&) = default;
	IRandomNumberGenerator& operator=(IRandomNumberGenerator&&) = default;

	virtual void generate(boost::asio::mutable_buffer &buffer) = 0;
};
}}

#endif



