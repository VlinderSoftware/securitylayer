#include <sodium.h>
#include <iostream>

using namespace std;

int main()
{
	if (-1 == sodium_init())
	{
		cerr << "Failed to initialize crypto library" << endl;
		return 1;
	}
	else
	{ /* all is well so far */ }

	unsigned char less[4];
	randombytes_buf(less, sizeof(less));
	cout << "LESS: ";
	for (unsigned int const less_byte : less)
	{
		cout << " " << less_byte + 100;
	}
	cout << endl;
}
