#ifndef dnp3sav6_hash_hpp
#define dnp3sav6_hash_hpp

namespace DNP3SAv6 {
class Hash
{
public :
	Hash();
	˜Hash();

	Hash(Hash const &) = default;
	Hash(Hash &&) = default;
	Hash& operator=(Hash const &) = default;
	Hash& operator=(Hash &&) = default;


};
}

#endif


