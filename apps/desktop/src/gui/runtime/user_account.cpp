#include "user_account.h"

#include <chrono>

namespace crossdesk {
namespace {

int64_t NowSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// 从设备 JSON 解析，容错缺字段
UserVisibleDevice ParseDevice(const nlohmann::json& d) {
  UserVisibleDevice dev;
  if (d.contains("device_id") && d["device_id"].is_string())
    dev.device_id = d["device_id"].get<std::string>();
  if (d.contains("alias") && d["alias"].is_string())
    dev.alias = d["alias"].get<std::string>();
  if (d.contains("online") && d["online"].is_boolean())
    dev.online = d["online"].get<bool>();
  return dev;
}

}  // namespace

UserAccount::UserAccount() = default;
UserAccount::~UserAccount() = default;

// ---- 状态查询 ----

UserLoginState UserAccount::State() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return state_;
}

bool UserAccount::IsSignedIn() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return state_ == UserLoginState::SignedIn && !token_.empty();
}

const std::string& UserAccount::Token() const {
  // 注意：返回引用，调用方应尽快使用；跨线程请先拷贝
  std::lock_guard<std::mutex> lock(mutex_);
  return token_;
}

const std::string& UserAccount::Username() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return username_;
}

const std::string& UserAccount::DisplayName() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return display_name_;
}

int64_t UserAccount::UserId() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return user_id_;
}

const std::string& UserAccount::LastError() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return last_error_;
}

std::vector<UserVisibleGroup> UserAccount::Groups() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return groups_;
}

std::vector<std::string> UserAccount::VisibleDeviceIds() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::string> ids;
  for (const auto& g : groups_) {
    for (const auto& d : g.devices) {
      ids.push_back(d.device_id);
    }
  }
  return ids;
}

bool UserAccount::CanAccess(const std::string& device_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  // 未登录时保持旧行为，允许手动输 ID 连接
  if (state_ != UserLoginState::SignedIn || token_.empty()) return true;
  // 员工登录状态下，只允许访问授权范围内的设备
  for (const auto& g : groups_) {
    for (const auto& d : g.devices) {
      if (d.device_id == device_id) return true;
    }
  }
  return false;
}

// ---- 状态变更 ----

void UserAccount::SetStateCallback(StateCallback cb) {
  std::lock_guard<std::mutex> lock(mutex_);
  state_cb_ = std::move(cb);
}

void UserAccount::SetState(UserLoginState state) {
  StateCallback cb;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    state_ = state;
    cb = state_cb_;
  }
  if (cb) cb(state);
}

bool UserAccount::BeginSignIn(const std::string& username,
                              const std::string& password,
                              nlohmann::json* request) {
  if (request == nullptr) return false;
  if (username.empty() || password.empty()) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      last_error_ = "用户名和密码不能为空";
    }
    SetState(UserLoginState::Failed);
    return false;
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    username_ = username;
    last_error_.clear();
  }

  *request = nlohmann::json{{"type", "user_login"},
                            {"username", username},
                            {"password", password}};

  SetState(UserLoginState::SigningIn);
  return true;
}

bool UserAccount::ApplyLoginResult(const nlohmann::json& message) {
  if (!message.is_object()) return false;
  if (message.value("type", "") != "user_login_result") return false;

  const std::string status = message.value("status", "");
  if (status != "success") {
    std::string code = message.value("error_code", "INTERNAL_ERROR");
    std::string reason = message.value("reason", "");
    if (reason.empty()) reason = code;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      last_error_ = reason;
      token_.clear();
      groups_.clear();
    }
    SetState(UserLoginState::Failed);
    return false;
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    token_ = message.value("token", "");
    if (token_.empty()) {
      last_error_ = "服务端未返回令牌";
      SetState(UserLoginState::Failed);
      return false;
    }

    const auto expires_in = message.value("expires_in", 0);
    expires_at_ = expires_in > 0 ? NowSeconds() + expires_in : 0;

    if (message.contains("user") && message["user"].is_object()) {
      const auto& u = message["user"];
      user_id_ = u.value("id", static_cast<int64_t>(0));
      username_ = u.value("username", username_);
      display_name_ = u.value("display_name", std::string{});
    }

    groups_.clear();
    if (message.contains("groups")) ParseGroups(message["groups"]);
    last_error_.clear();
  }

  SetState(UserLoginState::SignedIn);
  return true;
}

bool UserAccount::ApplyDeviceGroups(const nlohmann::json& message) {
  if (!message.is_object()) return false;
  if (message.value("type", "") != "device_groups") return false;
  if (message.value("status", "") != "success") return false;

  std::lock_guard<std::mutex> lock(mutex_);
  if (!message.contains("groups")) return false;
  ParseGroups(message["groups"]);
  return true;
}

void UserAccount::ParseGroups(const nlohmann::json& groups_array) {
  // 调用方已持锁
  groups_.clear();
  if (!groups_array.is_array()) return;

  for (const auto& g : groups_array) {
    if (!g.is_object()) continue;
    UserVisibleGroup group;
    group.id = g.value("id", static_cast<int64_t>(0));
    group.name = g.value("name", std::string{});
    group.description = g.value("description", std::string{});
    if (g.contains("devices") && g["devices"].is_array()) {
      for (const auto& d : g["devices"]) {
        if (!d.is_object()) continue;
        auto dev = ParseDevice(d);
        if (!dev.device_id.empty()) group.devices.push_back(std::move(dev));
      }
    }
    groups_.push_back(std::move(group));
  }
}

nlohmann::json UserAccount::BuildRefreshRequest() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return nlohmann::json{{"type", "get_device_groups"}, {"token", token_}};
}

void UserAccount::SignOut() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    token_.clear();
    user_id_ = 0;
    expires_at_ = 0;
    groups_.clear();
    display_name_.clear();
    last_error_.clear();
  }
  SetState(UserLoginState::SignedOut);
}

bool UserAccount::SessionExpired() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (expires_at_ <= 0) return false;
  return NowSeconds() >= expires_at_;
}

// ---- 持久化（只记用户名，不存密码）----

bool UserAccount::LoadPersistedIdentity(std::string* username) const {
  if (username == nullptr) return false;
  // 由上层（ConfigCenter）注入实际存储，此实现保持无副作用
  std::lock_guard<std::mutex> lock(mutex_);
  if (username_.empty()) return false;
  *username = username_;
  return true;
}

void UserAccount::RememberUsername(const std::string& username) {
  std::lock_guard<std::mutex> lock(mutex_);
  username_ = username;
}

}  // namespace crossdesk
