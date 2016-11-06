/*
* Result enums
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_PATH_RESULT_H__
#define BOTAN_X509_PATH_RESULT_H__

namespace Botan {

/**
* Certificate validation status code
*/
enum class Certificate_Status_Code {
   OK = 0,
   VERIFIED = 0,

   OCSP_RESPONSE_GOOD = 1,
   OCSP_SIGNATURE_OK = 2,

   // Local policy failures
   SIGNATURE_METHOD_TOO_WEAK = 1000,
   UNTRUSTED_HASH = 1001,
   NO_REVOCATION_DATA = 1002,

   // Time problems
   CERT_NOT_YET_VALID = 2000,
   CERT_HAS_EXPIRED = 2001,
   OCSP_NOT_YET_VALID = 2002,
   OCSP_HAS_EXPIRED = 2003,
   CRL_NOT_YET_VALID = 2004,
   CRL_HAS_EXPIRED = 2005,

   // Chain generation problems
   CERT_ISSUER_NOT_FOUND = 3000,
   CANNOT_ESTABLISH_TRUST = 3001,

   CERT_CHAIN_LOOP = 3002,

   // Validation errors
   POLICY_ERROR = 4000,
   INVALID_USAGE = 4001,
   CERT_CHAIN_TOO_LONG = 4002,
   CA_CERT_NOT_FOR_CERT_ISSUER = 4003,
   NAME_CONSTRAINT_ERROR = 4004,

   // Revocation errors
   CA_CERT_NOT_FOR_CRL_ISSUER = 4005,
   OCSP_CERT_NOT_LISTED = 4006,
   OCSP_BAD_STATUS = 4007,

   CERT_NAME_NOMATCH = 4008,

   UNKNOWN_CRITICAL_EXTENSION = 4009,

   OCSP_SIGNATURE_ERROR = 4501,

   OCSP_ISSUER_NOT_FOUND = 4502,
   OCSP_RESPONSE_MISSING_KEYUSAGE = 4503,
   OCSP_RESPONSE_INVALID = 4504,

   // Hard failures
   CERT_IS_REVOKED = 5000,
   CRL_BAD_SIGNATURE = 5001,
   SIGNATURE_ERROR = 5002,
};

/**
* Convert a status code to a human readable diagnostic message
* @param code the certifcate status
* @return string literal constant, or nullptr if code unknown
*/
const char* to_string(Certificate_Status_Code code);

}

#endif
