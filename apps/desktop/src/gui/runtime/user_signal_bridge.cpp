#include "user_signal_bridge.h"

#include <utility>

namespace crossdesk {

UserSignalBridge::UserSignalBridge(std::shared_ptr<UserAccount> account)
    : account_(std::move(account)) {}

UserSignalBridge::~UserSignalBridge() = default;

void UserSignalBridge::SetSender(SignalSendFn sender) {
  sender_ = std::move(sender);
}

bool UserSignalBridge::RequestSignIn(const std::string& username,
                                     const std::string& password) {
  if (!account_) return false;
  if (!sender_) return false;

  nlohmann::json request;
  if (!account_->BeginSignIn(username, password, &request)) return false;

  if (!sender_(request)) {
    // 发送失败：回退状态，避免卡在 SigningIn
    account_->SignOut();
    return false;
  }
  return true;
}

bool UserSignalBridge::RequestRefreshDevices() {
  if (!account_ || !sender_) return false;
  if (!account_->IsSignedIn()) return false;
  return sender_(account_->BuildRefreshRequest());
}

nlohmann::json UserSignalBridge::DecorateJoin(nlohmann::json input) const {
  // 未登录员工账号时保持原样（兼容旧行为）
  if (!account_ || !account_->IsSignedIn()) return input;
  // 携带 token，服务端据此校验设备是否在授权范围内
  input["token"] = account_->Token();
  return input;
}

bool UserSignalBridge::HandleIncoming(const nlohmann::json& message) {
  if (!account_ || !message.is_object()) return false;

  const std::string type = message.value("type", "");

  if (type == "user_login_result") {
    account_->ApplyLoginResult(message);
    return true;
  }

  if (type == "device_groups") {
    account_->ApplyDeviceGroups(message);
    return true;
  }

  return false;
}

void UserSignalBridge::OnConnected() {
  // 重连后若仍持有有效 token，主动刷新一次设备分组
  if (account_ && account_->IsSignedIn() && !account_->SessionExpired()) {
    RequestRefreshDevices();
  }
}

void UserSignalBridge::OnDisconnected() {
  // 信令断开不影响账号登录态：token 仍有效，重连后继续使用。
  // 仅当会话已过期才清理。
  if (account_ && account_->SessionExpired()) {
    account_->SignOut();
  }
}

}  // namespace crossdesk
