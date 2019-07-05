#include "hmac.hpp"

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 { 
	void digest_(Details::IHMAC &hmac, const_buffer const &data)
	{
		hmac.digest(data);
	}
}

