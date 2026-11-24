/*
 * CrossDesk - Windows DPAPI helper for remembered credentials.
 *
 * Wraps CryptProtectData / CryptUnprotectData so a stored password can only be
 * decrypted by the same Windows user on the same machine. A copied config file
 * is useless to another account.
 *
 * On non-Windows platforms both functions return false, so callers fall back to
 * not remembering the secret.
 */

#ifndef _DPAPI_SECRET_H_
#define _DPAPI_SECRET_H_

#include <string>

namespace crossdesk {

// Encrypt `plain` and return a base64 string suitable for a config file.
// Returns false when encryption is unavailable or fails.
bool ProtectSecret(const std::string& plain, std::string* encoded);

// Decrypt a string produced by ProtectSecret.
bool UnprotectSecret(const std::string& encoded, std::string* plain);

// Whether this build can protect secrets at all.
bool SecretStorageAvailable();

}  // namespace crossdesk

#endif  // _DPAPI_SECRET_H_
