# 雨婷工作台 · iOS 原生 App 部署手册（自用 / 免费 Apple ID）

> 目标：把现有的网页工作台打包成 iPhone 原生 App，直接用 Apple 健康（HealthKit）读取步数 / 心率 / 体重 / 睡眠 / 卡路里，**无需华为开发者审核**。
> 适用：iPhone + 免费 Apple ID + 只自己用（不上架 App Store）。

---

## 一、前置准备

1. 完整项目已生成在本机路径：
   `/Users/mac/WorkBuddy/2026-07-28-15-07-46`
2. 从 **Mac App Store** 安装 **Xcode**（免费，约 7GB）。安装后首次打开需同意许可协议。
3. 用**数据线**把 iPhone 连到 Mac，iPhone 上点「信任此电脑」。

---

## 二、打开 iOS 工程

在终端（项目目录）执行：

```bash
cd /Users/mac/WorkBuddy/2026-07-28-15-07-46
npx cap open ios
```

会自动用 Xcode 打开 `ios/App/App.xcworkspace`。

> 若命令报错，也可以直接双击 `ios/App/App.xcworkspace` 文件打开。

---

## 三、Xcode 一次性配置

1. 左侧选 **App**（在 TARGETS 下）→ 切到 **Signing & Capabilities**
   - **Team**：点下拉 → Add Account → 登录你的 Apple ID（免费个人账号即可）
   - **Bundle Identifier**：改成**唯一**字符串，例如 `com.yuting.workbench`
     （若提示 "unavailable"，改个变体如 `com.yuting.workbench.app`）
2. 点 **+ Capability** → 搜索 **HealthKit** → 双击添加（开启健康权限）
3. 顶部设备下拉框，选择你的 **iPhone**（需已连接并信任）

---

## 四、运行到手机

点 Xcode 左上角 **▶ 运行**（或快捷键 `Cmd + R`）。

- 首次运行会在 iPhone 上提示「未受信任的开发者」：
  去 iPhone **设置 → 通用 → VPN与设备管理 → 信任 [你的 Apple ID]**
- 回来再点一次 ▶ 运行，即可安装并启动 App。

---

## 五、使用健康数据

1. App 启动后进入 **健身页**
2. 点「🔐 授权同步华为运动健康」按钮
   - 在 iOS 原生壳里，这个按钮会**自动改走 Apple HealthKit**（不再走华为后端）
3. 系统弹出健康授权弹窗 → 点「允许」
4. 自动读取并填入：
   - 今日步数、活动卡路里
   - 最新体重、最新心率
   - 今日睡眠时长

### 如何顺带拿到华为数据？
如果你的 iPhone 上装了**华为运动健康 App**，并在其设置里开启了「同步到 Apple 健康」（或去 iPhone 健康 App → 数据源 → 授权华为写入），那么华为记录的运动数据会进入 iPhone 健康，本 App 就能**间接读到华为数据**，完全绕开华为开发者审核。

---

## 六、免费账号的限制

- 免费个人 Apple ID 签名的 App **每 7 天会失效**，之后需要重新用 Xcode 连手机点一次 ▶ 运行（重新签名）。
- HealthKit 仅在**真机**上生效，模拟器没有健康数据。

---

## 七、以后更新代码

改完 `app/` 下的源码后，在终端执行：

```bash
node build-dist.mjs      # 合并成 dist/index.html
npx cap sync ios        # 同步前端 + 插件到 iOS 工程
npx cap open ios        # 重新打开 Xcode
```

然后在 Xcode 点 ▶ 运行即可。

---

## 八、常见问题排查

- **SPM 报错**（CapApp-SPM 无法解析依赖）：确认 Mac 已联网（首次需从 GitHub 拉取 `capacitor-swift-pm`）；或重新执行 `npx cap sync ios`。
- **HealthKit 编译报错**：确认已按第三步添加 HealthKit capability。插件源码通过 SPM 自动引入（`ios/App/CapApp-SPM/Package.swift` 已引用 `YutingHealthkitBridge`）。
- **真机运行报签名 / 证书错误**：把 Bundle Identifier 改成另一个唯一值，或 Xcode → Settings → Accounts → 选中账号 → 点 Refresh 刷新签名。
- **点同步没反应 / 提示不支持**：确认是在 iPhone 真机上运行（非模拟器），且已通过 Xcode 安装（非浏览器打开的网页版）。
