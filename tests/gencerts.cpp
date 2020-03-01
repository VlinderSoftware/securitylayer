#include "../details/certificate.hpp"

using namespace std;
using namespace DNP3SAv6;

int main()
{
    using Details::Certificate;

    Certificate certificate(Certificate::generate("/CN=Device name", 30, "prime256v1", "sha256"));
    certificate.store(string("test.crt"), string("Crazy"));

    return 0;
}
