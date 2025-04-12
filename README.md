# Yunzai-WebChat-Plugin

一个 Yunzai-Bot 插件，它启动一个 WebSocket 服务器，允许非 QQ/微信 的自定义 WebSocket 前端连接，并将消息模拟成 Yunzai 的事件进行处理。

## 功能

*   启动一个可配置的 WebSocket 服务器。
*   通过 Token 对连接的客户端进行身份验证。
*   将来自认证客户端的 `message` 消息转换为 Yunzai 的 `message.private.*` 或 `message.group.*` 事件。
*   允许 Yunzai 插件通过 `e.reply()` 将消息发送回对应的 WebSocket 客户端。
*   模拟部分 Bot API 调用（如 `get_login_info`）和 `e.recall`, `e.pick*`, `e.bot` 等。

## 配置

插件配置文件位于 `Yunzai-Bot/config/config/WebChatPlugin.yaml`。

*   `server`:
    *   `host`: WebSocket 服务器监听的主机 (默认: `localhost`)
    *   `port`: WebSocket 服务器监听的端口 (默认: `2537`)
    *   `path`: WebSocket 服务器监听的路径 (默认: `/WebChatPlugin`)
*   `shared_token`: 用于客户端身份验证的共享密钥 (请务必修改为强密钥)。
*   `log_messages`: 是否在 Yunzai 控制台打印详细的收发消息内容 (默认: `false`)。

## 客户端协议

1.  **连接**: 连接到 `ws://<host>:<port><path>` (根据你的配置)。
2.  **认证**: 连接成功后，客户端 **必须** 发送 `auth` 消息：
    ```json
    {
      "type": "auth",
      "echo": "client-echo-123", // 可选的回声字段
      "payload": {
        "token": "YourSharedTokenHere",
        "user_id": "desired_user_id", // 客户端希望使用的用户ID
        "nickname": "Desired Nickname" // 客户端希望使用的昵称
      }
    }
    ```
    服务器会响应 `auth_response`：
    ```json
    {
      "type": "auth_response",
      "echo": "client-echo-123",
      "payload": {
        "status": "ok" or "failed",
        "message": "Authentication successful" or "Invalid token"
      }
    }
    ```
3.  **发送消息**: 认证成功后，客户端可以发送 `message` 消息给 Bot：
    ```json
    {
      "type": "message",
      "echo": "client-echo-456",
      "payload": {
        "message_type": "private", // "private" or "group"
        "group_id": "optional_group_id", // 如果 message_type 是 "group"
        "message": "你好，Bot！", // 可以是字符串或 Yunzai 支持的消息段数组 (插件会尝试解析)
        // 可选的 sender 信息
        "sender": {
            "card": "群名片" // 如果是群聊
        }
      }
    }
    ```
    服务器会响应 `message_receipt` 表明收到。
4.  **接收消息**: 当 Bot (通过 Yunzai 插件) 回复时，客户端会收到 `message` 类型的消息：
    ```json
    {
      "type": "message",
      "payload": {
        "post_type": "message",
        "message_type": "private", // or "group"
        "user_id": 12345678, // Bot 的 QQ 号
        "group_id": "optional_group_id",
        "sender": {
          "user_id": 12345678,
          "nickname": "BotNickname"
        },
        "message_id": "server-generated-message-id",
        "message": [ { "type": "text", "text": "你好，客户端！" } ], // Yunzai 消息段数组
        "raw_message": "你好，客户端！",
        "source": { "message_id": "client-message-id" } // 如果是引用回复
      }
    }
    ```
5.  **API 调用**: 客户端可以发送 `api_call` 请求：
    ```json
    {
        "type": "api_call",
        "echo": "client-echo-789",
        "payload": {
            "action": "get_login_info", // 例如
            "params": {} // API 所需参数
        }
    }
    ```
    服务器会响应 `api_response`。
6.  **心跳**: 客户端可以发送 `heartbeat` 保持连接：
    ```json
    { "type": "heartbeat", "echo": "hb-1" }
    ```
    服务器会响应 `heartbeat_response`。

## 注意事项

*   请确保安装了 `ws` 和 `ulid` 依赖 (`npm install ws ulid` 或 `pnpm install ws ulid` 在 Yunzai-Bot 根目录执行)。
*   修改配置文件中的 `shared_token` 为一个强密码。
*   这个插件模拟了适配器的核心功能，但并非完整的 OneBot v11 或其他标准协议实现。
*   部分模拟的 `e.*` 方法（如 `pick*`, `makeForwardMsg`）功能可能受限。
