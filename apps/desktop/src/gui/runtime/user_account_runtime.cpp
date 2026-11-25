/*
 * CrossDesk - employee account runtime wiring.
 *
 * GuiRuntime owns the account state machine but has no access to the Slint
 * windows (those belong to GuiApplication). A UI-update hook bridges the two
 * without inverting the ownership direction.
 */

#include <algorithm>
#include <cctype>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "runtime/gui_runtime.h"

#include "dpapi_secret.h"
#include "runtime/user_account.h"
#include "runtime/user_signal_bridge.h"

namespace crossdesk {

// [USER-ACCOUNT] Create the account state machine and its signaling bridge.
// Runs once during GUI startup, before any signaling connection exists.
void GuiRuntime::InitializeUserAccount() {
  if (user_account_) return;
  user_account_ = std::make_shared<UserAccount>();
  user_bridge_ = std::make_unique<UserSignalBridge>(user_account_);
  // Forward account protocol messages over the primary signaling channel.
  user_bridge_->SetSender([this](const nlohmann::json& payload) -> bool {
    if (!peer_) return false;
    const std::string text = payload.dump();
    return PeerSendSignalMessage(peer_, text.data(), text.size()) == 0;
  });
  user_account_->SetStateCallback([this](UserLoginState) {
    // Post through the hook so the GUI thread owns all Slint access.
    if (user_account_ui_hook_) user_account_ui_hook_();
  });
}

// [USER-ACCOUNT] Ask the server for an updated device list for this account.
void GuiRuntime::RefreshUserDeviceGroups() {
  if (user_bridge_) user_bridge_->RequestRefreshDevices();
}

// [USER-ACCOUNT] Snapshot the current device list as UI-ready entries.
std::vector<GuiRuntime::UserDeviceSnapshot> GuiRuntime::UserDevices() const {
  std::vector<UserDeviceSnapshot> out;
  if (!user_account_) return out;
  for (const auto& group : user_account_->Groups()) {
    for (const auto& device : group.devices) {
      out.push_back(UserDeviceSnapshot{device.device_id, device.alias,
                                       device.online});
    }
  }
  return out;
}


// [USER-ACCOUNT] Store the password (DPAPI-protected) when the user opted in.
void GuiRuntime::PersistAccountCredential(const std::string& password) {
  if (!config_center_ || !user_account_) return;
  const std::string username = user_account_->Username();
  if (username.empty()) return;

  if (!remember_password_) {
    ClearPersistedCredential();
    return;
  }

  std::string protected_blob;
  if (!ProtectSecret(password, &protected_blob) || protected_blob.empty()) {
    // DPAPI unavailable: do not fall back to plaintext.
    ClearPersistedCredential();
    return;
  }
  config_center_->SetAccountCredential(username, protected_blob);
}

// [USER-ACCOUNT] Drop the stored credential (sign-out or opt-out).
void GuiRuntime::ClearPersistedCredential() {
  if (config_center_) config_center_->ClearAccountCredential();
}

// [USER-ACCOUNT] Restore a remembered session at startup.
// Returns true when the bridge accepted the request, so the caller can keep the
// login gate hidden and let the reply arrive asynchronously.
bool GuiRuntime::TryRestoreAccountSession() {
  if (!config_center_ || !user_bridge_) return false;
  if (!config_center_->HasAccountCredential()) return false;

  const std::string username = config_center_->GetAccountUsername();
  const std::string blob = config_center_->GetAccountSecret();
  if (username.empty() || blob.empty()) return false;

  std::string password;
  if (!UnprotectSecret(blob, &password) || password.empty()) {
    // Blob belongs to another Windows user or the machine changed.
    ClearPersistedCredential();
    return false;
  }

  if (!user_bridge_->RequestSignIn(username, password)) return false;
  if (user_account_) user_account_->RememberUsername(username);
  return true;
}


// [NAV] 把账号分组展平成带分组名的设备行，并按搜索词过滤。
std::vector<GuiRuntime::DeviceUiRow> GuiRuntime::DeviceRows(
    const std::string& filter) const {
  std::vector<DeviceUiRow> rows;
  if (!user_account_) return rows;

  std::string needle = filter;
  // 简单的大小写不敏感（ASCII）
  std::transform(needle.begin(), needle.end(), needle.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  for (const auto& group : user_account_->Groups()) {
    for (const auto& device : group.devices) {
      DeviceUiRow row;
      row.device_id = device.device_id;
      row.alias = device.alias;
      row.group_id = group.id;
      row.group_name = group.name;
      row.online = device.online;
      row.has_password = device.has_saved_password;

      if (!needle.empty()) {
        std::string hay = device.alias + " " + device.device_id + " " + group.name;
        std::transform(hay.begin(), hay.end(), hay.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (hay.find(needle) == std::string::npos) continue;
      }
      rows.push_back(std::move(row));
    }
  }
  return rows;
}

// [NAV] 切换分组折叠状态。
void GuiRuntime::ToggleGroupCollapsed(int64_t group_id) {
  auto it = std::find(collapsed_groups_.begin(), collapsed_groups_.end(), group_id);
  if (it == collapsed_groups_.end()) {
    collapsed_groups_.push_back(group_id);
  } else {
    collapsed_groups_.erase(it);
  }
}

}  // namespace crossdesk
