#include "securitylayer.hpp"
#include "exceptions/contract.hpp"

using namespace std;
using namespace boost::asio;

namespace DNP3SAv6 {
SecurityLayer::SecurityLayer(
	  TransportFunction *transport_function
	, ApplicationLayer *application_layer
	)
	: transport_function_(transport_function)
	, application_layer_(application_layer)
{
	pre_condition(transport_function);
	pre_condition(application_layer);
}

void SecurityLayer::onLinkLost() noexcept
{
	reset();
}
void SecurityLayer::onApplicationReset() noexcept
{
	reset();
}

void SecurityLayer::postAPDU(const_buffer const &apdu)
{}
void SecurityLayer::postSPDU(const_buffer const &spdu)
{}
Errors SecurityLayer::postAPDU(const_buffer const &apdu, std::nothrow_t const&) noexcept
{
	return Errors::no_error__;
}
Errors SecurityLayer::postSPDU(const_buffer const &spdu, std::nothrow_t const&) noexcept
{
	return Errors::no_error__;
}

bool SecurityLayer::pollAPDU() const noexcept
{
	return false;
}
bool SecurityLayer::pollSPDU() const noexcept
{
	return false;
}

const_buffer SecurityLayer::getAPDU() const
{
	return const_buffer();
}
const_buffer SecurityLayer::getSPDU() const
{
	return const_buffer();
}
std::pair< const_buffer, Errors > SecurityLayer::getAPDU(std::nothrow_t const&) const
{
	return make_pair(const_buffer(), Errors::no_error__);
}

std::pair< const_buffer, Errors > SecurityLayer::getSPDU(std::nothrow_t const&) const
{
	return make_pair(const_buffer(), Errors::no_error__);
}

void SecurityLayer::reset() noexcept
{
	*this = SecurityLayer(transport_function_, application_layer_);
}
}


