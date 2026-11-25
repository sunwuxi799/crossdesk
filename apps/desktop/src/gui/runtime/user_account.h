/*
 * CrossDesk 客户端 - 员工账号登录与设备分组
 *
 * 独立于现有设备身份登录（DeviceLogin）：
 *   - DeviceLogin 负责“这台机器以什么设备身份上线”
 *   - UserAccount 负责“当前使用者是哪个员工、能看到哪些设备”
 * 两者互不干扰，员工未登录时客户端保持原行为。
 */

#ifndef _USER_ACCOUNT_H_
#define _USER_ACCOUNT_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace crossdesk {

// 分组内的一台设备
struct UserVisibleDevice {
  std::string device_id;
  std::string alias;
  bool online = false;
  // [SELF-SERVICE] 该设备是否已在本机保存连接密码（仅本地视图用）
  bool has_saved_password = false;
};

// 一个设备分组
struct UserVisibleGroup {
  int64_t id = 0;
  std::string name;
  std::string description;
  std::vector<UserVisibleDevice> devices;
};

// 员工登录状态
enum class UserLoginState {
  SignedOut,   // 未登录
  SigningIn,   // 已发出请求，等待结果
  SignedIn,    // 已登录
  Failed,      // 登录失败
};

// 自助操作结果
struct SelfServiceOutcome {
  bool ok = false;
  std::string error_code;
  std::string reason;
  int64_t group_id = 0;
  std::string device_id;
  std::string alias;
  std::string password;
  bool stored = false;
};

// 员工会话：保存 token、用户信息与设备分组
class UserAccount {
 public:
  using StateCallback = std::function<void(UserLoginState)>;

  UserAccount();
  ~UserAccount();

  UserAccount(const UserAccount&) = delete;
  UserAccount& operator=(const UserAccount&) = delete;

  // ---- 状态查询 ----

  UserLoginState State() const;
  bool IsSignedIn() const;
  const std::string& Token() const;
  const std::string& Username() const;
  const std::string& DisplayName() const;
  int64_t UserId() const;

  // 最近一次失败原因（供 UI 显示）
  const std::string& LastError() const;

  // 已登录用户可见的分组（含设备与在线状态）
  std::vector<UserVisibleGroup> Groups() const;

  // 拍平后的可见设备 ID 集合，用于连接前的权限自检
  std::vector<std::string> VisibleDeviceIds() const;

  // 该设备是否在授权范围内。未登录时返回 true（保持旧行为）。
  bool CanAccess(const std::string& device_id) const;

  // 设备显示名：优先别名，否则 device_id
  std::string DeviceDisplayName(const std::string& device_id) const;

  // ---- 状态变更 ----

  void SetStateCallback(StateCallback cb);

  // 发起登录：生成 user_login 请求 JSON，由调用方通过 WSS 发送。
  // 返回 true 表示请求已生成（状态切到 SigningIn）。
  bool BeginSignIn(const std::string& username, const std::string& password,
                   nlohmann::json* request);

  // 处理服务端 user_login_result
  bool ApplyLoginResult(const nlohmann::json& message);

  // 处理服务端 device_groups（刷新列表）
  bool ApplyDeviceGroups(const nlohmann::json& message);

  // 构造刷新请求
  nlohmann::json BuildRefreshRequest() const;

  // 退出登录（清除 token 与列表）
  void SignOut();

  // 会话是否即将/已经过期（按 expires_in 计算）
  bool SessionExpired() const;

  // 本地持久化（记住用户名，不保存密码）
  bool LoadPersistedIdentity(std::string* username) const;
  void RememberUsername(const std::string& username);

  // ---- 自助操作请求构造（第 3 步新增） ----

  // 创建自己的分组
  nlohmann::json BuildCreateGroupRequest(const std::string& name,
                                         const std::string& description) const;

  // 向自己的分组添加设备
  nlohmann::json BuildAddDeviceRequest(int64_t group_id,
                                       const std::string& device_id,
                                       const std::string& alias) const;

  // 保存连接密码到云端
  nlohmann::json BuildSavePasswordRequest(const std::string& device_id,
                                          const std::string& password,
                                          bool remember) const;

  // 读取云端保存的连接密码
  nlohmann::json BuildGetPasswordRequest(const std::string& device_id) const;

  // 修改设备别名（同步到近期连接）
  nlohmann::json BuildSetAliasRequest(const std::string& device_id,
                                      const std::string& alias) const;

  // ---- 自助操作响应处理（第 3 步新增） ----

  // 统一解析 <type>_result 消息。只有 type 以 _result 结尾且
  // 前缀属于自助操作时才消费，返回 true。
  bool ApplySelfServiceResult(const nlohmann::json& message);

  // 最近一次自助操作结果
  SelfServiceOutcome LastOutcome() const;

  // 按 device_id 查找设备（含别名与在线状态）
  bool FindDevice(const std::string& device_id, UserVisibleDevice* out) const;
  // 分组结构变化时触发一次刷新（由 GuiRuntime 注入）
  void SetSelfServiceRefreshHook(std::function<void()> hook);

 private:
  void SetState(UserLoginState state);
  void ParseGroups(const nlohmann::json& groups_array);

  mutable std::mutex mutex_;
  UserLoginState state_ = UserLoginState::SignedOut;
  std::string token_;
  std::string username_;
  std::string display_name_;
  std::string last_error_;
  int64_t user_id_ = 0;
  int64_t expires_at_ = 0;
  std::vector<UserVisibleGroup> groups_;
  SelfServiceOutcome last_outcome_;
  std::function<void()> self_service_refresh_hook_;
  StateCallback state_cb_;
};

}  // namespace crossdesk

#endif  // _USER_ACCOUNT_H_
