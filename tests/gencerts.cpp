#include "../details/certificate.hpp"

using namespace DNP3SAv6;

int main()
{
    using Details::Certificate;

    Certificate certificate(Certificate::generate("/CN=Device name", 30, "prime256v1", "sha256"));

    return 0;
}
