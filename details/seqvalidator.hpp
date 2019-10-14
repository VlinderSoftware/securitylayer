#ifndef dnp3sav6_details_seqvalidator_hpp
#define dnp3sav6_details_seqvalidator_hpp

#include <cstdint>

namespace DNP3SAv6 { namespace Details { 
class SEQValidator
{
public :
    enum Result {
          invalid_seq__
        , old_seq__
        , repeat_seq__
        , next_seq__
        , new_seq__
        };

	SEQValidator() = default;
	virtual ~SEQValidator() = default;

	SEQValidator(SEQValidator const&) = delete;
	SEQValidator(SEQValidator &&) = delete;
	SEQValidator& operator=(SEQValidator const&) = delete;
	SEQValidator& operator=(SEQValidator &&) = delete;

    Result validateSEQ(std::uint32_t incoming_seq) const noexcept;    // called to see if a message might be valid
    void setLatestIncomingSEQ(std::uint32_t incoming_seq) noexcept; // called to tell the layer what the latest one we received is
    void reset() noexcept;

private :
	std::uint32_t next_expected_seq_ = 0; // note: 0 is not a valid sequence number, so as long as this is 0, we will accept anything except 0
};
}}

#endif
