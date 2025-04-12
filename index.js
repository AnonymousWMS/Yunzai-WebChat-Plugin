import WebSocket, { WebSocketServer } from 'ws';
import { ulid } from 'ulid';
import makeConfig from '../../lib/plugins/config.js'; // 引入Yunzai的配置工具

// --- 日志记录 ---
// 优先使用 Bot.logger，如果不存在则使用 console
const logger = global.Bot?.logger ?? console;
const pluginName = 'WebChatPlugin'; // 插件名称，用于日志

// --- 配置加载 ---
const defaultConfig = {
  // WebSocket 服务器配置
  server: {
    host: 'localhost', // 监听的主机地址
    port: 2538,       // 监听的端口 (避免与 webchat.js 的 2536 冲突)
    path: '/WebChatPlugin' // WebSocket 路径
  },
  // 身份验证 Token (建议修改为你自己的复杂 Token)
  shared_token: 'PleaseChangeThisSecretToken_WebChatPlugin',
  // (可选) 是否在 Yunzai 控制台显示收发的消息内容 (可能刷屏)
  log_messages: false
};

const { config, configSave } = await makeConfig(pluginName, defaultConfig, {
  // 配置文件的提示信息
  tips: [
    `欢迎使用 ${pluginName} !`,
    `这是一个将 WebSocket 连接模拟成 Yunzai 消息的插件。`,
    `请确保客户端连接到 ws://${defaultConfig.server.host}:${defaultConfig.server.port}${defaultConfig.server.path}`,
    `并在连接后发送 auth 消息进行身份验证。`,
    `配置文件路径: config/config/${pluginName}.yaml`
  ],
});

logger.info(`[${pluginName}] 正在加载...`);

// --- 插件主类 ---
class WebChatPlugin {
  constructor() {
    this.id = pluginName; // 用于标识
    this.name = "WebChat Plugin Adapter";
    this.clients = new Map(); // 存储连接的客户端: clientId -> ws
    this.clientContext = new Map(); // 存储客户端上下文: clientId -> { user_id, nickname, isAuthenticated, etc. }
    this.wss = null; // WebSocket 服务器实例
    this.bot = global.Bot; // 获取全局 Bot 对象
    this.self_id = this.bot?.uin; // 使用当前登录 Bot 的 QQ 号作为 self_id
    this.task = {}; // 添加空的 task 对象以满足加载器

    // 定义一个虚拟的 adapter 对象，用于填充 eventData
    this.virtualAdapter = {
        id: this.id,
        name: this.name,
        // 可以根据需要添加更多 adapter 的模拟方法或属性
        // 例如，如果插件需要调用 this.adapter.getGroupList()，就需要在这里模拟
        // 为了简化，这里只包含基础信息
        sendMsg: (data, msg) => this.sendMsg(data, msg), // 将sendMsg指向插件的方法
        makeLog: (level, msg, userId = null) => this.makeLog(level, msg, userId) // 使用插件的日志方法
    };

    if (!this.bot) {
      logger.error(`[${pluginName}] global.Bot 未定义，插件无法运行。`);
      return;
    }
    if (!this.self_id) {
        logger.warn(`[${pluginName}] 未获取到 Bot.uin，self_id 将为 null，可能影响部分功能。`);
    }

    this.initWebSocketServer();
  }

  // --- 日志封装 ---
  makeLog(level, msg, userId = null) {
      const logPrefix = `[${pluginName}]`;
      const message = Array.isArray(msg) ? msg.join(' ') : msg;
      const logUserId = userId || this.self_id; // 如果没有提供 userId，默认使用 bot 的 uin

      if (this.bot && this.bot.makeLog) {
          // Yunzai 的日志通常包含颜色等格式，第一个元素是前缀
          this.bot.makeLog(level, [logPrefix, ...Array.isArray(msg) ? msg : [msg]], logUserId);
      } else {
          // 降级到 console.log
          const levelUpper = String(level).toUpperCase();
          console.log(`[${levelUpper}] ${logPrefix} ${message}${logUserId ? ` (User: ${logUserId})` : ''}`);
      }
  }


  // --- 初始化 WebSocket 服务器 ---
  initWebSocketServer() {
    if (this.wss) {
      this.makeLog('warn', 'WebSocket 服务器已初始化。');
      return;
    }
    const { host, port, path } = config.server;
    try {
      this.wss = new WebSocketServer({ host, port, path });
      this.makeLog('info', `WebSocket 服务器监听在 ws://${host}:${port}${path}`);

      this.wss.on('connection', (ws, req) => {
        const clientId = ulid();
        const remoteAddress = req.socket.remoteAddress || req.headers['x-forwarded-for'] || 'Unknown IP';
        this.clients.set(clientId, ws);
        // 初始上下文，标记未认证
        this.clientContext.set(clientId, { remoteAddress, isAuthenticated: false, user_id: null, nickname: null });
        this.makeLog('info', `客户端连接: ${clientId} from ${remoteAddress}`);

        // 发送连接成功消息给客户端
        ws.send(JSON.stringify({ type: 'connected', payload: { clientId: clientId, server: this.name } }));

        // 处理消息
        ws.on('message', (message) => {
          try {
            const messageString = message.toString();
            // 简单的消息大小限制
            if (messageString.length > 10 * 1024) {
              this.makeLog('warn', `来自 ${clientId} 的消息过大，已丢弃。`);
              ws.send(JSON.stringify({ type: 'error', message: 'Message too large' }));
              return;
            }
            const data = JSON.parse(messageString);
            if (config.log_messages) {
              this.makeLog('debug', `收到来自 ${clientId} 的消息: ${messageString.substring(0, 200)}${messageString.length > 200 ? '...' : ''}`);
            }
            this.handleClientMessage(data, clientId, ws);
          } catch (error) {
            this.makeLog('error', [`解析来自 ${clientId} 的消息失败: ${error}`, message.toString().substring(0, 100)]);
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid JSON format' }));
          }
        });

        // 处理关闭
        ws.on('close', (code, reason) => {
          const reasonStr = String(reason || 'N/A').substring(0, 100);
          this.makeLog('info', `客户端断开连接: ${clientId}. Code: ${code}, Reason: ${reasonStr}`);
          this.clients.delete(clientId);
          this.clientContext.delete(clientId);
        });

        // 处理错误
        ws.on('error', (error) => {
          this.makeLog('error', `客户端 ${clientId} WebSocket 错误: ${error}`);
          // 出错时也清理资源
          if (this.clients.has(clientId)) {
            this.clients.delete(clientId);
            this.clientContext.delete(clientId);
             try { ws.terminate(); } catch {} // 强制关闭
          }
        });
      });

      // 处理服务器错误
      this.wss.on('error', (error) => {
        this.makeLog('error', `WebSocket 服务器错误: ${error}`);
        this.wss = null; // 标记服务器已不可用
      });

      // 处理服务器关闭
      this.wss.on('close', () => {
        this.makeLog('info', 'WebSocket 服务器已关闭。');
        this.wss = null;
      });

    } catch (error) {
      this.makeLog('error', `初始化 WebSocket 服务器失败: ${error}`);
    }
  }

  // --- 处理客户端消息 ---
  handleClientMessage(data, clientId, ws) {
    const echo = data.echo; // 用于客户端追踪响应
    const currentContext = this.clientContext.get(clientId) || { isAuthenticated: false };

    switch (data.type) {
      case 'auth':
        const clientToken = data.payload?.token;
        let isAuthenticated = false;
        let authStatus = 'failed';
        let authMessage = '无效的 Token';

        if (clientToken && clientToken === config.shared_token) {
          isAuthenticated = true;
          authStatus = 'ok';
          authMessage = '身份验证成功';
          this.makeLog('info', `客户端 ${clientId} 使用 Token 验证成功。`);
        } else {
          this.makeLog('warn', `客户端 ${clientId} 身份验证失败。无效或缺失 Token。`);
          // 可以选择在验证失败时断开连接
          // setTimeout(() => ws.terminate(), 100);
        }

        // 更新客户端上下文，存储认证状态和用户信息
        this.clientContext.set(clientId, {
          ...currentContext,
          user_id: data.payload?.user_id || `web_${clientId.substring(0, 8)}`, // 从客户端获取或生成默认
          nickname: data.payload?.nickname || `Web User ${clientId.substring(0, 4)}`, // 从客户端获取或生成默认
          isAuthenticated: isAuthenticated,
        });

        // 发送认证响应给客户端
        ws.send(JSON.stringify({ type: 'auth_response', echo, payload: { status: authStatus, message: authMessage } }));
        break;

      case 'message':
        // 检查是否已认证
        if (!currentContext.isAuthenticated) {
          this.makeLog('warn', `收到来自未认证客户端 ${clientId} 的消息，已丢弃。`);
          ws.send(JSON.stringify({ type: 'error', echo, message: '需要身份验证' }));
          return;
        }
        // 检查消息格式
        if (!data.payload || !data.payload.message) {
          this.makeLog('warn', `来自 ${clientId} 的消息格式无效：缺少 payload 或 message`);
          ws.send(JSON.stringify({ type: 'error', echo, message: '无效的消息格式' }));
          return;
        }
        // 处理传入的消息，转换为 Yunzai 事件
        this.processIncomingMessageEvent(data.payload, clientId);
        // 告知客户端消息已收到（但不一定处理成功）
        ws.send(JSON.stringify({ type: 'message_receipt', echo, payload: { status: 'received' } }));
        break;

      case 'api_call':
        if (!currentContext.isAuthenticated) {
             this.makeLog('warn', `收到来自未认证客户端 ${clientId} 的 API 调用，已丢弃。`);
             ws.send(JSON.stringify({ type: 'error', echo, message: '需要身份验证' }));
             return;
         }
        if (!data.payload || !data.payload.action) {
            this.makeLog('warn', `来自 ${clientId} 的 api_call 格式无效：缺少 payload 或 action`);
            ws.send(JSON.stringify({ type: 'error', echo, message: '无效的 api_call 格式' }));
            return;
        }
        // 处理 API 调用 (需要实现 handleApiCall)
        this.handleApiCall(clientId, data.payload.action, data.payload.params, echo);
        break;

      case 'heartbeat':
        if (config.log_messages) {
          this.makeLog('debug', `收到来自 ${clientId} 的心跳`);
        }
        ws.send(JSON.stringify({ type: 'heartbeat_response', echo, payload: { timestamp: Date.now() } }));
        break;

      default:
        this.makeLog('warn', `收到来自 ${clientId} 的未知消息类型 '${data.type}'`);
        ws.send(JSON.stringify({ type: 'error', echo, message: `未知的消息类型: ${data.type}` }));
    }
  }

  // --- 处理来自客户端的 API 调用 ---
  async handleApiCall(clientId, action, params, echo) {
      const clientContext = this.clientContext.get(clientId);
      const ws = this.clients.get(clientId);
      if (!ws || !clientContext) return; // 客户端已断开

      this.makeLog('info', `收到来自 ${clientId} 的 API 调用: ${action}, 参数: ${JSON.stringify(params).substring(0,100)}...`);
      let responsePayload = { success: false, message: '未实现的 API 调用', data: null };

      try {
          // 这里模拟一些常见的 Bot API 调用
          switch (action) {
              case 'get_login_info':
                  responsePayload = {
                      success: true,
                      data: {
                          user_id: this.self_id,
                          nickname: this.bot?.nickname || "Bot"
                      }
                  };
                  break;
              case 'get_friend_list':
              case 'get_group_list':
              case 'get_group_member_list':
                  // 这些需要真正调用 Bot 的方法，如果 Bot 对象和方法存在
                  if (this.bot && typeof this.bot[action] === 'function') {
                      // 注意：Yunzai 的 getFriendList 等可能不接受参数或需要特定格式
                      // 这里简化处理，实际使用时需要适配
                      const result = await this.bot[action]();
                      responsePayload = { success: true, data: result };
                  } else {
                       responsePayload.message = `Bot 对象或方法 ${action} 不可用`;
                  }
                  break;
              // 可以添加更多 API 调用处理
              default:
                   responsePayload.message = `未知的 API action: ${action}`;
          }
      } catch (error) {
          this.makeLog('error', `处理 API 调用 ${action} 出错: ${error}`);
          responsePayload.message = `处理 API 调用时出错: ${error.message}`;
      }

      // 发送 API 响应给客户端
      ws.send(JSON.stringify({ type: 'api_response', echo, payload: responsePayload }));
  }

  // --- 处理收到的消息并派发为 Yunzai 事件 ---
  processIncomingMessageEvent(payload, clientId) {
    const clientInfo = this.clientContext.get(clientId);
    // 如果找不到上下文信息，则无法处理
    if (!clientInfo) {
        this.makeLog('warn', `处理消息时未找到客户端 ${clientId} 的上下文信息。`);
        return;
    }

    const user_id = clientInfo.user_id;
    const nickname = clientInfo.nickname;
    const isAuthenticated = clientInfo.isAuthenticated;
    const userRole = isAuthenticated ? 'master' : 'guest'; // 根据认证状态分配角色
    const isMaster = isAuthenticated; // 通常插件用 isMaster 判断权限

    const message_type = payload.message_type || 'private'; // 默认私聊
    const raw_message = typeof payload.message === 'string' ? payload.message : JSON.stringify(payload.message);

    // 构造 Yunzai 事件对象 (e)
    // 1. 先创建基础属性
    const eventData = {
      adapter: this.virtualAdapter,
      self_id: this.self_id,
      uin: this.self_id,
      user_id: user_id,
      post_type: "message",
      message_type: message_type,
      sub_type: payload.sub_type || (message_type === 'group' ? 'normal' : 'friend'),
      message_id: payload.message_id || ulid(),
      group_id: message_type === 'group' ? (payload.group_id || 'webchat_group') : undefined,
      seq: Date.now(),
      rand: Math.random(),
      font: "WebChatFont",
      raw_message: raw_message,
      message: this.parseMsg(payload.message),
      sender: {
        user_id: user_id,
        nickname: nickname,
        card: message_type === 'group' ? (payload.sender?.card || nickname) : undefined,
        role: userRole,
      },
      toString: () => raw_message,
      isMaster: isMaster,
      logText: `[${message_type}] ${nickname}(${user_id})${message_type === 'group' ? ` G(${payload.group_id || 'webchat_group'})` : ''}: ${raw_message.substring(0, 50)}${raw_message.length > 50 ? '...' : ''}` // 注意 group_id 的获取方式
    };

    // 2. 再添加依赖 eventData 自身的方法
    eventData.reply = (msg, quote = false) => this.reply(clientId, eventData, msg, quote);
    eventData.recall = () => this.recall(clientId, eventData.message_id);
    eventData.pickUser = (uid) => this.pickFriend(uid || user_id); // pickFriend 不依赖 eventData
    eventData.pickMember = (gid, uid) => this.pickMember(gid || eventData.group_id, uid || user_id);
    eventData.pickGroup = (gid) => this.pickGroup(gid || eventData.group_id);
    eventData.bot = this.getBotApi(eventData);
    eventData.makeForwardMsg = async (forwardMsg) => {
        this.makeLog('debug', `[makeForwardMsg 模拟] 收到转发请求: ${JSON.stringify(forwardMsg).substring(0,100)}...`);
        let text = "--- 转发消息 ---\n";
        if (Array.isArray(forwardMsg)) {
            for (const node of forwardMsg) {
                const nodeUser = node.nickname || node.user_id || "未知用户";
                let nodeMsg = "[消息内容]";
                if (typeof node.message === 'string') {
                    nodeMsg = node.message;
                } else if (Array.isArray(node.message)) {
                    nodeMsg = node.message.map(segment => segment.text || `[${segment.type}]`).join('');
                }
                text += `${nodeUser}: ${nodeMsg}\n`;
            }
        } else {
            text += "[无法解析的转发内容]";
        }
        text += "--- 结束转发 ---";
        return [{ type: 'text', text }];
    };


    // 派发事件给 Yunzai
    try {
      const eventName = `${eventData.post_type}.${eventData.message_type}.${eventData.sub_type}`; // e.g., message.private.friend
      this.bot.em(eventName, eventData);
      if (config.log_messages) {
        this.makeLog('info', `已派发事件 '${eventName}' from client ${clientId} (User: ${user_id}, Role: ${userRole})`);
      }
    } catch (dispatchError) {
      this.makeLog('error', `派发事件 '${eventData.post_type}.${eventData.message_type}.${eventData.sub_type}' for ${clientId} 出错: ${dispatchError}`);
    }
  }

  // --- 实现 e.reply ---
  reply(clientId, sourceEvent, msg, quote = false) {
    const ws = this.clients.get(clientId);
    if (!ws) {
      this.makeLog('error', `尝试回复时未找到客户端 ${clientId}`);
      return null; // 或返回一个表示失败的 Promise
    }

    if (config.log_messages) {
        this.makeLog('debug', `[reply] 准备回复 ${clientId} (SourceMsgId: ${sourceEvent.message_id}): ${JSON.stringify(msg).substring(0, 100)}...`);
    }

    const replyMessageId = ulid(); // 为这条回复生成新的 message_id

    // 构造发送给客户端的消息结构
    const messageToSend = {
      type: 'message',
      payload: {
        post_type: 'message',
        message_type: sourceEvent.message_type, // 回复到原始消息类型 (private/group)
        user_id: this.self_id, // 消息来源是 Bot
        group_id: sourceEvent.group_id, // 带上群 ID (如果是群聊)
        sender: { // 模拟 Bot 的发送者信息
          user_id: this.self_id,
          nickname: this.bot?.nickname || "Bot" // 使用 Yunzai Bot 的昵称
        },
        message_id: replyMessageId, // 新消息的 ID
        message: this.parseMsg(msg), // 解析要发送的消息内容
        raw_message: (typeof msg === 'string' || typeof msg === 'number') ? String(msg) : `[复杂消息: ${Array.isArray(msg) ? msg.map(m=>m.type).join(',') : typeof msg}]`,
        // 添加引用信息 (如果 quote 为 true 且原消息有 ID)
        source: quote && sourceEvent.message_id ? { message_id: sourceEvent.message_id } : undefined,
      }
    };

    // 发送消息
    this.sendMsgToClient(clientId, messageToSend);

    // Yunzai 的 reply 通常需要返回一个包含 message_id 的对象或 Promise
    // 这里返回一个简单的对象
    return { message_id: replyMessageId };
  }

   // --- 实现 e.recall ---
  async recall(clientId, message_id) {
      const ws = this.clients.get(clientId);
      if (!ws) {
        this.makeLog('error', `尝试撤回时未找到客户端 ${clientId}`);
        return false;
      }
      this.makeLog('info', `请求客户端 ${clientId} 尝试撤回消息 ${message_id}`);
      // 通知客户端尝试撤回
      this.sendMsgToClient(clientId, { type: 'notice', payload: { notice_type: 'recall_attempt', message_id: message_id } });
      // 假设客户端会处理这个通知，这里直接返回 true (无法确认客户端是否真的撤回)
      return true;
  }

  // --- 消息段解析 (简化版) ---
  // 将 Yunzai 的消息对象或字符串转换为客户端可能理解的格式
  // 这里简单地将数组或对象转为 JSON 字符串，或保持字符串不变
  parseMsg(msg) {
      if (typeof msg === 'string' || typeof msg === 'number') {
          // 如果是纯文本或数字，包装成 Yunzai 的 text segment 格式
          return [{ type: 'text', text: String(msg) }];
      } else if (Array.isArray(msg)) {
          // 如果已经是数组 (可能是 Yunzai 的消息段)，直接返回
          // TODO: 可以根据需要进一步处理，比如转换图片 segment 为 URL
          return msg;
      } else if (typeof msg === 'object' && msg !== null) {
          // 如果是单个对象 (可能是某种特殊消息)，尝试放入数组
           // TODO: 需要更智能的判断，这里可能不健壮
           if (msg.type) { // 假设它像一个消息段
               return [msg];
           } else {
               // 否则，转为文本表示
               return [{ type: 'text', text: `[Object: ${JSON.stringify(msg).substring(0,50)}...]` }];
           }
      }
      // 其他情况返回空数组或错误提示
      return [{ type: 'text', text: '[无法解析的消息]' }];
  }

  // --- 发送消息到指定客户端 ---
  sendMsgToClient(clientId, message) {
    const ws = this.clients.get(clientId);
    if (ws && ws.readyState === WebSocket.OPEN) {
      try {
        const messageString = JSON.stringify(message);
         if (config.log_messages) {
            this.makeLog('debug', `发送给 ${clientId}: ${messageString.substring(0, 200)}${messageString.length > 200 ? '...' : ''}`);
         }
        ws.send(messageString);
        return true; // 表示发送尝试成功
      } catch (error) {
        this.makeLog('error', `发送消息给 ${clientId} 失败: ${error}`);
        return false; // 表示发送尝试失败
      }
    } else {
      this.makeLog('warn', `尝试发送消息时客户端 ${clientId} 不可用或未连接。`);
      return false;
    }
  }

  // --- 模拟适配器的 sendMsg 方法 ---
  // 这个方法可能在某些插件内部被调用 (e.g., Bot.sendMsg)
  // 它需要确定目标用户/群聊对应的 clientId
  async sendMsg(data, msg) {
      // data 可能包含 user_id 或 group_id
      const targetUserId = data.user_id;
      const targetGroupId = data.group_id; // WebChat 可能没有真实群聊概念

      // 查找与目标用户 ID 匹配的已连接客户端
      let targetClientId = null;
      for (const [clientId, context] of this.clientContext.entries()) {
          // 简单匹配 user_id (假设 WebChat 用户 ID 是唯一的)
          // 对于群聊，这里简化为：如果指定了 group_id，则发送给所有在该 "群聊" (如果客户端上报了) 且在线的客户端
          // 这部分逻辑需要根据实际前端如何处理群聊来调整
          if (targetUserId && context.user_id === targetUserId) {
              targetClientId = clientId;
              break;
          }
          // TODO: 添加群聊查找逻辑 (如果需要)
      }

      if (targetClientId) {
          this.makeLog('info', `[sendMsg] 找到了目标客户端 ${targetClientId} for user ${targetUserId}`);
          const messageToSend = { /* ... 构造类似 reply 中的消息结构 ... */
               type: 'message',
               payload: {
                  post_type: 'message',
                  message_type: targetGroupId ? 'group' : 'private',
                  user_id: this.self_id,
                  group_id: targetGroupId,
                  sender: { user_id: this.self_id, nickname: this.bot?.nickname || "Bot" },
                  message_id: ulid(),
                  message: this.parseMsg(msg),
                  raw_message: typeof msg === 'string' ? msg : '[复杂消息]',
               }
           };
          const success = this.sendMsgToClient(targetClientId, messageToSend);
          return success ? { message_id: messageToSend.payload.message_id } : null;
      } else {
          this.makeLog('warn', `[sendMsg] 未找到与 user_id=${targetUserId} 或 group_id=${targetGroupId} 匹配的在线客户端。`);
          return null; // 没有找到目标
      }
  }


  // --- 模拟 pick 方法 ---
  // 这些方法返回的对象结构尽量模仿 Yunzai，但功能受限
   pickFriend(user_id) {
      const context = Array.from(this.clientContext.values()).find(ctx => ctx.user_id === user_id);
      return {
          // 返回一个模拟的 Friend 对象
          user_id: user_id,
          nickname: context?.nickname || `Web User (${user_id})`,
          sendMsg: (msg) => this.sendMsg({ user_id }, msg), // 提供发送消息的方法
          getInfo: async () => ({ user_id, nickname: context?.nickname || "Unknown" }), // 模拟获取信息
          avatar: `https://via.placeholder.com/100?text=${user_id}` // 模拟头像 URL
      };
  }

  pickMember(group_id, user_id) {
       const context = Array.from(this.clientContext.values()).find(ctx => ctx.user_id === user_id);
       // 模拟群成员对象
       return {
           group_id: group_id,
           user_id: user_id,
           nickname: context?.nickname || `Web User (${user_id})`,
           card: context?.nickname || "", // 模拟群名片
           sendMsg: (msg) => this.sendMsg({ group_id, user_id }, msg), // 私聊该成员
           getInfo: async () => ({ user_id, nickname: context?.nickname || "Unknown", group_id }),
           avatar: `https://via.placeholder.com/100?text=${user_id}` // 模拟头像 URL
       };
   }

   pickGroup(group_id) {
       // 模拟群对象
       return {
           group_id: group_id,
           group_name: `Web Chat Group (${group_id})`, // 模拟群名
           sendMsg: (msg) => this.sendMsg({ group_id }, msg), // 发送群消息
           getInfo: async () => ({ group_id, group_name: `Web Chat Group (${group_id})` }),
           getMemberList: async () => { // 模拟获取群成员列表
                return Array.from(this.clientContext.values())
                            .filter(ctx => ctx.isAuthenticated) // 只返回在线且认证的
                            .map(ctx => ({ user_id: ctx.user_id, nickname: ctx.nickname }));
            },
            pickMember: (uid) => this.pickMember(group_id, uid) // 提供 pickMember 方法
       };
   }

   // --- 模拟 Bot API 对象 ---
   getBotApi(eventData) {
        // 返回一个包含常用 Bot 方法的对象，这些方法会调用插件内部的实现
        const botApi = {
            uin: this.self_id,
            nickname: this.bot?.nickname || "Bot",
            version: { // 模拟版本信息
                id: this.id,
                name: this.name,
                version: '1.0.0' // 插件版本
            },
            // 转发 sendMsg 调用
            sendMsg: (targetData, msg) => this.sendMsg(targetData, msg),
            // 转发 pick 调用
            pickFriend: (uid) => this.pickFriend(uid),
            pickMember: (gid, uid) => this.pickMember(gid, uid),
            pickGroup: (gid) => this.pickGroup(gid),
            // 转发 recall (尝试使用核心 recall，失败则模拟)
            recallMsg: async (messageId) => {
                if (this.bot && this.bot.recallMsg) {
                    // 尝试使用主 bot 的 recall，需要 group_id (可能为 null)
                    return this.bot.recallMsg(eventData.group_id, messageId || eventData.message_id);
                } else {
                    // 备用方案：通过客户端通知模拟撤回
                    // 需要 clientId，这里无法直接获取，暂时移除或标记为不可靠
                    this.makeLog('warn', '[bot.recallMsg] 无法获取 clientId，无法模拟撤回，请确保主 Bot 对象支持 recallMsg');
                    // return this.recall(??clientId??, messageId || eventData.message_id);
                    return false;
                }
            },
            // 模拟获取列表的方法 (可能需要调用真实 Bot 对象的方法)
            getFriendList: async () => {
                // 尝试调用真实 Bot 方法，否则返回当前连接的客户端
                 if (this.bot?.adapter?.icqq?.fl) return Array.from(this.bot.adapter.icqq.fl.values()); // 示例：尝试获取 ICQQ 适配器的好友列表
                 return Array.from(this.clientContext.values()).map(ctx => ({ user_id: ctx.user_id, nickname: ctx.nickname }));
            },
            getGroupList: async () => {
                // 同上，尝试获取真实群列表
                if (this.bot?.adapter?.icqq?.gl) return Array.from(this.bot.adapter.icqq.gl.values());
                return [{ group_id: 'webchat_group', group_name: 'Web Chat Group (webchat_group)' }]; // 返回默认模拟群
            },
            // ... 可以添加更多模拟的 Bot API 方法
        };
        return botApi;
    }


  // --- 插件卸载/关闭处理 ---
  shutdown() {
    this.makeLog('info', '开始关闭 WebSocket 服务器...');
    if (this.wss) {
      // 关闭所有客户端连接
      this.clients.forEach(ws => {
        try {
          ws.terminate(); // 强制关闭
        } catch (e) {
            this.makeLog('error', `关闭客户端连接时出错: ${e}`);
        }
      });
      this.clients.clear();
      this.clientContext.clear();

      // 关闭服务器
      this.wss.close((err) => {
        if (err) {
          this.makeLog('error', `关闭 WebSocket 服务器时出错: ${err}`);
        } else {
          this.makeLog('info', 'WebSocket 服务器已成功关闭。');
        }
        this.wss = null;
      });
    } else {
        this.makeLog('info', 'WebSocket 服务器未运行。');
    }
  }
}

// --- 实例化并导出插件 ---
// Yunzai 会自动加载 plugins 目录下的 JS 文件导出的类或对象
// 将实例存储在全局，方便需要时访问（例如通过其他插件）
// 注意：Yunzai 加载机制可能有所不同，标准做法是导出类或对象
const webChatPluginInstance = new WebChatPlugin();

// 导出插件实例或类，供 Yunzai 加载
// 不同的 Yunzai 版本或加载器可能期望不同的导出方式
// 常见的是导出类本身，或者导出一个包含插件实例的对象
// export default webChatPluginInstance; // 方式一：导出实例
export { WebChatPlugin }; // 方式二：导出类，Yunzai 会自动 new

// 监听退出信号，尝试优雅关闭
process.on('SIGINT', () => {
    logger.info(`[${pluginName}] 收到 SIGINT 信号，准备关闭...`);
    webChatPluginInstance.shutdown();
    // 可能需要稍微延迟退出，给关闭操作一点时间
    setTimeout(() => process.exit(0), 500);
});
process.on('SIGTERM', () => {
    logger.info(`[${pluginName}] 收到 SIGTERM 信号，准备关闭...`);
    webChatPluginInstance.shutdown();
    setTimeout(() => process.exit(0), 500);
});

logger.info(`[${pluginName}] 加载完成。`);
