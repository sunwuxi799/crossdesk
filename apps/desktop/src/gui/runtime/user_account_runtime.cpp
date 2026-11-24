/*
 * CrossDesk - employee account runtime wiring.
 *
 * GuiRuntime owns the account state machine but has no access to the Slint
 * windows (those belong to GuiApplication). A UI-update hook bridges the two
 * without inverting the ownership direction.
 */

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "runtime/gui_runtime.h"
#include "runtime/user_account.h"
#include "runtime/user_signal_bridge.h"

namespace crossdesk {

// [USER-ACCOUNT] Create the account state machine and its signaling bridge.
// Runs once during GUI startup, before any signaling connection exists.
void GuiRuntime::InitializeUserAccount() {
  if (user_account_) return;
  user_account_ = std::make_shared<UserAccount>();
  user_bridge_ = std::make_unique<UserSignalBridge>(user_account_);
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

}  // namespace crossdesk
