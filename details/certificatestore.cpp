#include "certificatestore.hpp"
#include "certificate.hpp"
#include <algorithm>

using namespace std;

namespace DNP3SAv6 { namespace Details {
/*virtual */size_t CertificateStore::count() const/* override = 0*/
{
    return certificates_.size();
}
/*virtual */void CertificateStore::add(Certificate const &certificate)/* override = 0*/
{
    certificates_.push_back(certificate);
}
/*virtual */void CertificateStore::remove(DistinguishedName const &name)/* override = 0*/
{
    auto which(find_if(certificates_.begin(), certificates_.end(), [name](Certificate const &certificate){ return certificate.getSubjectName() == name; }));
    if (which != certificates_.end())
    {
        certificates_.erase(which);
    }
    else
    { /* nothing to remove */ }
}
/*virtual */void CertificateStore::remove(std::string const &name)/* override = 0*/
{
    ICertificateStore::remove(name);
}
/*virtual */bool CertificateStore::verify(Certificate const &certificate) const/* override = 0*/
{
    bool retval(false);
    // find the certificate of the issuer
    auto issuer(certificate.getIssuerName());
    auto issuer_certificate(find_if(certificates_.begin(), certificates_.end(), [=](Certificate const &certificate){ return certificate.getSubjectName() == issuer; }));

    if (issuer_certificate != certificates_.end())
    {
        // verify the signature
        retval = issuer_certificate->verify(certificate);
    }
    else
    { /* not found, won't verify */ }

    return retval;
}
}}
