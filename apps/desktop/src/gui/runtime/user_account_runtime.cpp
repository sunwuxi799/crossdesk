/*
 * CrossDesk - employee account runtime wiring.
 *
 * Bridges the UserAccount state machine into the GUI runtime and the Slint
 * windows. Kept in its own translation unit like device_trust_runtime.cpp so
 * the account feature stays isolated from unrelated runtime concerns.
 */

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "crossdesk_ui.h"
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
    BroadcastUserAccountState();
  });
}

// [USER-ACCOUNT] Push current account state into every Slint window.
void GuiRuntime::BroadcastUserAccountState() {
  if (!user_account_ || !ui_) return;

  std::vector<ui::UserDeviceEntry> items;
  for (const auto& group : user_account_->Groups()) {
    for (const auto& device : group.devices) {
      ui::UserDeviceEntry entry{};
      entry.device_id = slint::SharedString(device.device_id);
      entry.alias = slint::SharedString(device.alias);
      entry.online = device.online;
      items.push_back(std::move(entry));
    }
  }

  auto model = std::make_shared<slint::VectorModel<ui::UserDeviceEntry>>(items);
  const bool signed_in = user_account_->IsSignedIn();
  const bool signing_in = user_account_->State() == UserLoginState::SigningIn;
  const std::string display = user_account_->DisplayName().empty()
                                  ? user_account_->Username()
                                  : user_account_->DisplayName();
  const std::string error = user_account_->LastError();

  const auto apply = [&](auto* window) {
    if (!window) return;
    window->set_user_signed_in(signed_in);
    window->set_user_signing_in(signing_in);
    window->set_user_devices(model);
    window->set_user_display_name(slint::SharedString(display));
    window->set_user_error_text(slint::SharedString(error));
  };
  apply(ui_->main);
  apply(ui_->wall);
}

// [USER-ACCOUNT] Ask the server for an updated device list for this account.
void GuiRuntime::RefreshUserDeviceGroups() {
  if (user_bridge_) user_bridge_->RequestRefreshDevices();
}

}  // namespace crossdesk
