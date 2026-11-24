/*
 * CrossDesk 客户端 - 员工账号信令桥接
 *
 * 负责把 UserAccount 的状态机接到实际的 WSS 收发路径：
 *   - 发送 side：把 BeginSignIn 生成的消息交给信令客户端
 *   - 接收 side：在消息分发处识别 user_login_result / device_groups
 *
 * 设计为无侵入：未启用员工登录时完全不参与消息处理。
 */

#ifndef _USER_SIGNAL_BRIDGE_H_
#define _USER_SIGNAL_BRIDGE_H_

#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

#include "user_account.h"

namespace crossdesk {

// 发送回调：由调用方注入实际的 WSS 发送实现
using SignalSendFn = std::function<bool(const nlohmann::json&)>;

class UserSignalBridge {
 public:
  explicit UserSignalBridge(std::shared_ptr<UserAccount> account);
  ~UserSignalBridge();

  UserSignalBridge(const UserSignalBridge&) = delete;
  UserSignalBridge& operator=(const UserSignalBridge&) = delete;

  // 注入发送实现（信令连接建立后调用）
  void SetSender(SignalSendFn sender);

  // ---- 由 UI 触发 ----
  // 发起登录；内部调用 UserAccount::BeginSignIn 并发送
  bool RequestSignIn(const std::string& username, const std::string& password);

  // 请求刷新设备分组
  bool RequestRefreshDevices();

  // 已登录时带 token 的 join 消息增强。
  // 若未登录则原样返回 input。
  nlohmann::json DecorateJoin(nlohmann::json input) const;

  // ---- 由信令接收路径调用 ----
  // 返回 true 表示该消息已被本桥接消费（调用方不应再处理）
  bool HandleIncoming(const nlohmann::json& message);

  // 连接建立/断开时同步登录态
  void OnConnected();
  void OnDisconnected();

  UserAccount* Account() const { return account_.get(); }

 private:
  std::shared_ptr<UserAccount> account_;
  SignalSendFn sender_;
};

}  // namespace crossdesk

#endif  // _USER_SIGNAL_BRIDGE_H_
