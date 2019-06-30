#include <iostream>
#include <openssl/rand.h>
#include <boost/asio.hpp>
#include "details/randomnumbergenerator.hpp"

using namespace std;
using namespace DNP3SAv6;
using namespace boost::asio;

using Details::RandomNumberGenerator;

int main()
{
	unsigned char less[4];
	RandomNumberGenerator rng;
	mutable_buffer less_buffer(less, sizeof(less));
	rng.generate(less_buffer);

	cout << "LESS: ";
	for (unsigned int const less_byte : less)
	{
		cout << " " << less_byte + 100;
	}
	cout << endl;
}
