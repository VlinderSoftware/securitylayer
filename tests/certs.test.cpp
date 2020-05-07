/* Copyright 2019  Ronald Landheer-Cieslak
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. */
#include "catch.hpp"
#include "../details/certificate.hpp"
#include <boost/filesystem.hpp>

using namespace std;
using namespace DNP3SAv6;
using DNP3SAv6::Details::Certificate;
namespace fs = boost::filesystem;

TEST_CASE( "Try to create a one-key instance", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "sha256")));
}

TEST_CASE( "Try to create an RSA + ECDH instance", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, 2048, "prime256v1", "sha256")));
}

TEST_CASE( "Try to create an ECDSA + ECDH instance", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "prime256v1", "sha256")));
}

TEST_CASE( "Try to create, store, and reload a one-key cert, no private key, with human-readable content", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), true);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string()));
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload a one-key cert, no private key, no human-readable content", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), false);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string()));
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload a one-key cert, with private key, with human-readable content, don't re-read private keys", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", true);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string()));
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload a one-key cert, with private key, with human-readable content, re-read private keys", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", true);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password"));
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload a one-key cert, with private key, with human-readable content, re-read private keys with wrong passkey", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", true);
        {
            bool caught(false);
            try
            {
                Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "wrong password"));
            }
            catch (runtime_error const &)
            {
                caught = true;
            }
            REQUIRE(caught);
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload a one-key cert, with private key, without human-readable content, don't re-read private keys", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", false);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string()));
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload a one-key cert, with private key, without human-readable content, re-read private keys", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", false);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password"));
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload a one-key cert, with private key, without human-readable content, re-read private keys with wrong passkey", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", false);
        {
            bool caught(false);
            try
            {
                Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "wrong password"));
            }
            catch (runtime_error const &)
            {
                caught = true;
            }
            REQUIRE(caught);
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an RSA + ECDH cert, no private key, with human-readable content", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, 2048, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), true);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string()));
#if defined(OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH) && OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
#endif
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an RSA + ECDH cert, no private key, no human-readable content", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, 2048, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), false);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string()));
#if defined(OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH) && OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
#endif
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an RSA + ECDH cert, with private key, with human-readable content, don't re-read private keys", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, 2048, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", true);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string()));
#if defined(OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH) && OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
#endif
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an RSA + ECDH cert, with private key, with human-readable content, re-read private keys", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, 2048, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", true);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password"));
#if defined(OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH) && OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
#endif
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an RSA + ECDH cert, with private key, with human-readable content, re-read private keys with wrong passkey", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, 2048, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", true);
        {
            bool caught(false);
            try
            {
                Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "wrong password"));
            }
            catch (runtime_error const &)
            {
                caught = true;
            }
            REQUIRE(caught);
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an RSA + ECDH cert, with private key, without human-readable content, don't re-read private keys", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, 2048, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", false);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string()));
#if defined(OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH) && OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
#endif
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an RSA + ECDH cert, with private key, without human-readable content, re-read private keys", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, 2048, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", false);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password"));
#if defined(OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH) && OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
#endif
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an RSA + ECDH cert, with private key, without human-readable content, re-read private keys with wrong passkey", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, 2048, "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", false);
        {
            bool caught(false);
            try
            {
                Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "wrong password"));
            }
            catch (runtime_error const &)
            {
                caught = true;
            }
            REQUIRE(caught);
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an ECDSA + ECDH cert, no private key, no human-readable content", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), false);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string()));
#if defined(OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH) && OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
#endif
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an ECDSA + ECDH cert, with private key, with human-readable content, don't re-read private keys", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", true);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string()));
#if defined(OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH) && OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
#endif
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an ECDSA + ECDH cert, with private key, with human-readable content, re-read private keys", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", true);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password"));
#if defined(OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH) && OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
#endif
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an ECDSA + ECDH cert, with private key, with human-readable content, re-read private keys with wrong passkey", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", true);
        {
            bool caught(false);
            try
            {
                Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "wrong password"));
            }
            catch (runtime_error const &)
            {
                caught = true;
            }
            REQUIRE(caught);
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an ECDSA + ECDH cert, with private key, without human-readable content, don't re-read private keys", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", false);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string()));
#if defined(OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH) && OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
#endif
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an ECDSA + ECDH cert, with private key, without human-readable content, re-read private keys", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", false);
        {
            Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password"));
#if defined(OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH) && OPTION_REQUIRE_CURVE_IOD_AND_PARAMETERS_TO_MATCH
            REQUIRE(self_signed_pub_only.getECDHPublicKey() == certificate.getECDHPublicKey());
#endif
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}

TEST_CASE( "Try to create, store, and reload an ECDSA + ECDH cert, with private key, without human-readable content, re-read private keys with wrong passkey", "[certs]" ) {
    Certificate certificate(Certificate::generate("/CN=Device name", Certificate::makeOptions(30, "prime256v1", "prime256v1", "sha256")));
    {
        certificate.store((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "some password", false);
        {
            bool caught(false);
            try
            {
                Certificate self_signed_pub_only(Certificate::load((fs::temp_directory_path() / "sav6-self-signed.crt").string(), "wrong password"));
            }
            catch (runtime_error const &)
            {
                caught = true;
            }
            REQUIRE(caught);
        }
        fs::remove(fs::temp_directory_path() / "sav6-self-signed.crt");
    }
}
