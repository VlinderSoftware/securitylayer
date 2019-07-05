#ifndef dnp3sav6_wrappedkeydata_hpp
#define dnp3sav6_wrappedkeydata_hpp

#include <cstdint>
#include "keywrapalgorithm.hpp"
#include "macalgorithm.hpp"

namespace DNP3SAv6 {
	/* There are a few variable-length fields in this struct as defined by the WG15 working document. IEEE 1815-2012 
	 * defines it with similar variable-length fields for SAv5. I am not a fan of variable-length fields: it makes 
	 * specs ambiguous and makes implementations harder to verify. Hence, the present proposal removes a number of 
	 * options, as well as all public data, and leaves only the keys and the MAC. This leaves two variants of the 
	 * structure to be defined - one per MAC size. 
	 * The following table summarizes our options:
	 * +-----+-----+--------------------------+------------------+
	 * | KWA | MAL | Session key size (bytes) | MAC size (bytes) |
	 * +-----+-----+--------------------------+------------------+
	 * |  2  |  3  |                       32 |                8 |
	 * |  2  |  4  |                       32 |               16 |
	 * |  2  |  7  |                       32 |                8 |
	 * |  2  |  8  |                       32 |               16 |
	 * |  2  |  9  |                       32 |                8 |
	 * |  2  | 10  |                       32 |               16 |
	 * +-----+-----+--------------------------+------------------+
	 * which leaves us with two structures and a meta-function to know which structure to use.
	 * If/when we add more KWAs or MALs, this may change, but the structure will always only depend on those two 
	 * parameters, at least according to my current proposal, as proposed on the SATF mailing list on June 29.
	 */

	struct WrappedKeydataT8
	{
		std::byte control_direction_session_key_[32];
		std::byte monitoring_direction_session_key_[32];
		std::byte mac_value_[8];
	};
	struct WrappedKeydataT16
	{
		std::byte control_direction_session_key_[32];
		std::byte monitoring_direction_session_key_[32];
		std::byte mac_value_[16];
	};
	template < KeyWrapAlgorithm kwa, MACAlgorithm mal >
	struct WrappedKeyData;
	template < > struct WrappedKeyData< KeyWrapAlgorithm::nist_sp800_38f_aes_256__, MACAlgorithm::hmac_sha_256_truncated_8__	 > { typedef WrappedKeydataT8 type; };
	template < > struct WrappedKeyData< KeyWrapAlgorithm::nist_sp800_38f_aes_256__, MACAlgorithm::hmac_sha_256_truncated_16__	 > { typedef WrappedKeydataT16 type; };
	template < > struct WrappedKeyData< KeyWrapAlgorithm::nist_sp800_38f_aes_256__, MACAlgorithm::hmac_sha_3_256_truncated_8__	 > { typedef WrappedKeydataT8 type; };
	template < > struct WrappedKeyData< KeyWrapAlgorithm::nist_sp800_38f_aes_256__, MACAlgorithm::hmac_sha_3_256_truncated_16__  > { typedef WrappedKeydataT16 type; };
	template < > struct WrappedKeyData< KeyWrapAlgorithm::nist_sp800_38f_aes_256__, MACAlgorithm::hmac_blake2s_truncated_8__	 > { typedef WrappedKeydataT8 type; };
	template < > struct WrappedKeyData< KeyWrapAlgorithm::nist_sp800_38f_aes_256__, MACAlgorithm::hmac_blake2s_truncated_16__	 > { typedef WrappedKeydataT16 type; };
}

#endif

