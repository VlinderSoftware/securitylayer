#include "certificatestore.hpp"
#include "certificate.hpp"
#include <set>
#include <stack>
#include "opaque.hpp"
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
    auto which(find(name));
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
    auto issuer_certificate(find(issuer));

    if (issuer_certificate != certificates_.end())
    {
        // verify the signature
        retval = issuer_certificate->verify(certificate);
    }
    else
    { /* not found, won't verify */ }

    return retval;
}
/*virtual */std::vector< unsigned char > CertificateStore::encode(Details::DistinguishedName const &certificate_name, bool encode_chain) const/* = 0*/
{
    std::stack< Certificates::const_iterator > certificates;
    std::set< DistinguishedName > names;

    // find the certificate
    certificates.push(find(certificate_name));
    if (certificates.top() == certificates_.end())
    {
        throw std::runtime_error("Certificate not found");
    }
    else
    { /* all is well */ }
    names.insert(certificates.top()->getSubjectName());
    // if we encode the chain, find the issuers until we loop
    bool done(false);
    while (done)
    {
        auto issuer_name(certificates.top()->getIssuerName());
        done = (names.find(issuer_name) != names.end());
        if (!done)
        {
            auto issuer_certificate(find(issuer_name));
            if (issuer_certificate != certificates_.end())
            {
                certificates.push(issuer_certificate);
            }
            else
            {
                done = true;
            }
        }
        else
        { /* we're done */ }
    }
    
    std::deque< Opaque > encoded_certificates;
    while (!certificates.empty())
    {
        Opaque encoded_certificate(certificates.top()->encode());
    }
}

CertificateStore::Certificates::const_iterator CertificateStore::find(DistinguishedName const &name) const
{
    return find_if(certificates_.begin(), certificates_.end(), [=](Certificate const &certificate){ return certificate.getSubjectName() == name; });
}
CertificateStore::Certificates::iterator CertificateStore::find(DistinguishedName const &name)
{
    return find_if(certificates_.begin(), certificates_.end(), [=](Certificate const &certificate){ return certificate.getSubjectName() == name; });
}
}}
