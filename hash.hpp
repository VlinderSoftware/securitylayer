#ifndef dnp3sav6_hash_hpp
#define dnp3sav6_hash_hpp

static_assert(DNP3SAV6_PROFILE_HPP_INCLUDED, "profile.hpp should be pre-included in CMakeLists.txt");

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


