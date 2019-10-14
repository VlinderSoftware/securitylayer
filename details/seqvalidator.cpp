#include "seqvalidator.hpp"

namespace DNP3SAv6 { namespace Details { 
SEQValidator::Result SEQValidator::validateSEQ(std::uint32_t incoming_seq) const noexcept
{
    if (next_expected_seq_ == 0)
    {
        if (incoming_seq == 0)
        {
            return invalid_seq__;
        }
        else
        {
            return new_seq__;
        }
    }
    else
    {
        if (incoming_seq == 0)
        {
            return invalid_seq__;
        }
        else if (incoming_seq < next_expected_seq_ - 1)
        {
            return old_seq__;
        }
        else if (incoming_seq == next_expected_seq_ - 1)
        {
            return repeat_seq__;
        }
        else if (incoming_seq == next_expected_seq_)
        {
            return next_seq__;
        }
        else
        {
            return new_seq__;
        }
    }
}

void SEQValidator::setLatestIncomingSEQ(std::uint32_t incoming_seq) noexcept
{
    next_expected_seq_ = incoming_seq + 1;
}
void SEQValidator::reset() noexcept
{
    next_expected_seq_ = 0;
}
}}
