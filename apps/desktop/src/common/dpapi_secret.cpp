#include "dpapi_secret.h"

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>

#include <vector>
#endif

namespace crossdesk {
namespace {

#ifdef _WIN32

// Minimal base64 so the encrypted blob stays printable inside the config file.
const char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string ToBase64(const std::vector<unsigned char>& data) {
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  size_t i = 0;
  while (i + 2 < data.size()) {
    const unsigned int triple =
        (static_cast<unsigned int>(data[i]) << 16) |
        (static_cast<unsigned int>(data[i + 1]) << 8) |
        static_cast<unsigned int>(data[i + 2]);
    out.push_back(kAlphabet[(triple >> 18) & 0x3F]);
    out.push_back(kAlphabet[(triple >> 12) & 0x3F]);
    out.push_back(kAlphabet[(triple >> 6) & 0x3F]);
    out.push_back(kAlphabet[triple & 0x3F]);
    i += 3;
  }
  const size_t remaining = data.size() - i;
  if (remaining == 1) {
    const unsigned int triple = static_cast<unsigned int>(data[i]) << 16;
    out.push_back(kAlphabet[(triple >> 18) & 0x3F]);
    out.push_back(kAlphabet[(triple >> 12) & 0x3F]);
    out.append("==");
  } else if (remaining == 2) {
    const unsigned int triple =
        (static_cast<unsigned int>(data[i]) << 16) |
        (static_cast<unsigned int>(data[i + 1]) << 8);
    out.push_back(kAlphabet[(triple >> 18) & 0x3F]);
    out.push_back(kAlphabet[(triple >> 12) & 0x3F]);
    out.push_back(kAlphabet[(triple >> 6) & 0x3F]);
    out.push_back('=');
  }
  return out;
}

int Base64Value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

bool FromBase64(const std::string& text, std::vector<unsigned char>* out) {
  if (out == nullptr) return false;
  out->clear();
  int accumulator = 0;
  int bits = 0;
  for (char c : text) {
    if (c == '=' || c == '\n' || c == '\r') continue;
    const int value = Base64Value(c);
    if (value < 0) return false;
    accumulator = (accumulator << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out->push_back(static_cast<unsigned char>((accumulator >> bits) & 0xFF));
    }
  }
  return true;
}

#endif  // _WIN32

}  // namespace

bool SecretStorageAvailable() {
#ifdef _WIN32
  return true;
#else
  return false;
#endif
}

bool ProtectSecret(const std::string& plain, std::string* encoded) {
  if (encoded == nullptr) return false;
  encoded->clear();
#ifdef _WIN32
  if (plain.empty()) return false;

  DATA_BLOB input{};
  input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()));
  input.cbData = static_cast<DWORD>(plain.size());

  DATA_BLOB output{};
  // Scope the protection to the current user; no extra entropy is needed
  // because the config file is already per-user.
  if (!CryptProtectData(&input, L"crossdesk.account", nullptr, nullptr, nullptr,
                        CRYPTPROTECT_UI_FORBIDDEN, &output)) {
    return false;
  }

  std::vector<unsigned char> blob(output.pbData, output.pbData + output.cbData);
  LocalFree(output.pbData);
  *encoded = ToBase64(blob);
  return !encoded->empty();
#else
  (void)plain;
  return false;
#endif
}

bool UnprotectSecret(const std::string& encoded, std::string* plain) {
  if (plain == nullptr) return false;
  plain->clear();
#ifdef _WIN32
  if (encoded.empty()) return false;

  std::vector<unsigned char> blob;
  if (!FromBase64(encoded, &blob) || blob.empty()) return false;

  DATA_BLOB input{};
  input.pbData = blob.data();
  input.cbData = static_cast<DWORD>(blob.size());

  DATA_BLOB output{};
  if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &output)) {
    return false;
  }

  plain->assign(reinterpret_cast<const char*>(output.pbData), output.cbData);
  LocalFree(output.pbData);
  return true;
#else
  (void)encoded;
  return false;
#endif
}

}  // namespace crossdesk
