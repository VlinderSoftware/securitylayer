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
