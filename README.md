
---

### [敬告](#敬告)<br>
> **禁止在中国大陆的任何平台传播此项目！**<br>
> **禁止将本仓库中的任何内容用于违法活动或用于盈利目的！**<br>
> **本项目仅供学习交流及测试，使用本项目中的内容所造成的一切后果，均由使用者承担！**<br>

---

## [仓库简介](#仓库简介)<br>
> **本[仓库](https://github.com/XiangwanGuan/Shadowrocket)由[向晚](https://t.me/xiangwanguan)维护，提供[Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118)的多款[配置文件](#配置功能介绍)、一款[融合模块](#融合模块介绍)，部分资源由生成器自动构建；**<br>
> **如果此项目对您有帮助，欢迎给予Star；若有其他需求或问题，请提交Issues！**<br>

---

### [配置功能介绍](#配置功能介绍)<br>
#### 功能介绍<br>
> 所有配置默认使用**TUN模式**接管全部流量；<br>
> 使用加密的**DoH**进行DNS解析，并劫持未加密的查询请求；<br>
> 提供有效的**劫持保护**与**隐私保护策略**；<br>
> Apple/Microsoft/Google单独分流；<br>
> ChatGPT/Copilot/Gemini等AI工具单独分流；<br>
> WeChat/Telegram单独分流，降低因策略变化导致封号的风险；<br>
> 国内地址与国际地址，国内媒体与国际媒体，分别进行分流处理；<br>
> **本仓库所使用的规则集源于[blackmatrix7](https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/QuantumultX)，由[GitHub Actions](https://github.com/XiangwanGuan/Shadowrocket/blob/main/.github/workflows/Update%20RuleFiles.yml)每日自动同步**；<br>

#### 如何安装<br>
> 使用安装Shadowrocket的手机访问此页面，点击安装链接，一键跳转安装；<br>
> 如无法加载配置，请将全局路由切换至[代理]模式，或自行检查网络；<br>

#### 修改分流<br>
> **仅适用于包含代理分组的配置；**<br>
> 打开Shadowrocket首页，下拉进入`代理分组`，选择你想要修改的代理分组，选择策略即可；<br>

---

### [基础配置介绍](#基础配置介绍)<br>
#### 配置功能介绍<br>
> [基础配置](https://github.com/XiangwanGuan/Shadowrocket/blob/main/Rules.conf)的默认策略既是完善的策略，如无特殊需求，无需自行调整；<br>
> 代理分组内的策略自动分流，自动测试节点的可用性，优先选择延迟较低的节点，无需手动切换节点；<br>

#### 使用必看<br>
> 你所使用的节点，**尽量包含`港美新`这三项**；<br>
> 如**不完全包含**这三个地区的节点，则需要自行修改代理分组/正则，或使用[完整配置](https://github.com/XiangwanGuan/Shadowrocket/blob/main/RulesFull.conf)或[精简配置](https://github.com/XiangwanGuan/Shadowrocket/blob/main/RulesLite.conf)；<br>
> 基础配置默认规则如下：<br>
> 国内应用直接连接；<br>
> Telegram使用`新加坡节点`，Google，ChatGPT/Copilot/Gemini，使用`美国节点`；<br>
> 其他规则及未匹配到的规则使用`香港节点`；<br>
> 为了保证完全接管流量，本配置**默认使用`香港节点`兜底**，**首页的节点选择将被分组替代，完全失效**；<br>
> **此配置是最适合大众的配置，添加后无需调整，如节点包含`港新美`，建议使用此配置！**<br>

#### 配置安装<br>
[![一键安装 基础配置](https://img.shields.io/static/v1?label=一键安装&message=Rules.conf&color=grey&logo=googledocs&logoColor=white&labelColor=orange&messageColor=white)](https://lowertop.github.io/Shadowrocket-First/redirect.html?url=shadowrocket://config/add/https://xiangwanguan.github.io/Shadowrocket/Rules.conf "一键安装：基础配置")<br>

---

### [完整配置介绍](#完整配置介绍)<br>
#### 配置功能介绍<br>
> [完整配置](https://github.com/XiangwanGuan/Shadowrocket/blob/main/RulesFull.conf)基于[基础配置](https://github.com/XiangwanGuan/Shadowrocket/blob/main/Rules.conf)构建，包含更多代理分组：`港台日新美`，**默认使用`首页节点`进行代理**，可更自由的配置代理分组，其余配置完全相同；<br>
> **如需要更自由的代理分组及自动分流，建议使用此配置！**<br>

#### 配置安装<br>
[![一键安装 完整配置](https://img.shields.io/static/v1?label=一键安装&message=RulesFull.conf&color=grey&logo=googledocs&logoColor=white&labelColor=orange&messageColor=white)](https://lowertop.github.io/Shadowrocket-First/redirect.html?url=shadowrocket://config/add/https://xiangwanguan.github.io/Shadowrocket/RulesFull.conf "一键安装：完整配置")<br>

---

### [精简配置介绍](#精简配置介绍)<br>
#### 配置功能介绍<br>
> [精简配置](https://github.com/XiangwanGuan/Shadowrocket/blob/main/RulesLite.conf)基于[基础配置](https://github.com/XiangwanGuan/Shadowrocket/blob/main/Rules.conf)构建，除不包含代理分组以外，其余配置完全相同；<br>
> **如不需要代理分组及自动分流，强烈建议使用此配置！**<br>

#### 配置安装<br>
[![一键安装 精简配置](https://img.shields.io/static/v1?label=一键安装&message=RulesLite.conf&color=grey&logo=googledocs&logoColor=white&labelColor=orange&messageColor=white)](https://lowertop.github.io/Shadowrocket-First/redirect.html?url=shadowrocket://config/add/https://xiangwanguan.github.io/Shadowrocket/RulesLite.conf "一键安装：精简配置")<br>

---

### [回国配置介绍](#回国配置介绍)<br>
#### 配置功能介绍<br>
> [回国配置](https://github.com/XiangwanGuan/Shadowrocket/blob/main/RulesBackCN.conf)基于[精简配置](https://github.com/XiangwanGuan/Shadowrocket/blob/main/RulesLite.conf)构建，适合外国华侨使用，国内域名代理，其余域名直连；<br>
> **此配置需搭配`回国机场`使用，不适合国内用户使用！**<br>

#### 配置安装<br>
[![一键安装 回国分流配置](https://img.shields.io/static/v1?label=一键安装&message=RulesBackCN.conf&color=grey&logo=googledocs&logoColor=white&labelColor=orange&messageColor=white)](https://lowertop.github.io/Shadowrocket-First/redirect.html?url=shadowrocket://config/add/https://xiangwanguan.github.io/Shadowrocket/RulesBackCN.conf "一键安装：回国分流配置")<br>

---

### [融合模块介绍](#融合模块介绍)<br>
#### 模块安装<br>
[![一键安装 融合模块](https://img.shields.io/static/v1?label=一键安装&message=融合模块&color=grey&logo=lvgl&logoColor=white&labelColor=blue&messageColor=white)](https://lowertop.github.io/Shadowrocket-First/redirect.html?url=shadowrocket://install?module=https://xiangwanguan.github.io/Shadowrocket/Module.sgmodule "一键安装：融合模块")<br>

#### 模块说明<br>
> **[融合模块](https://github.com/XiangwanGuan/Shadowrocket/blob/main/Module.sgmodule)由[GitHub Actions](https://github.com/XiangwanGuan/Shadowrocket/blob/main/.github/workflows/Update%20ModuleRules.yml)调用[生成器](https://github.com/XiangwanGuan/Shadowrocket/blob/main/ModuleBuild/ModuleBuild.py)依据[规则](https://github.com/XiangwanGuan/Shadowrocket/blob/main/ModuleBuild/BuildList.conf)而构建，随规则变化，不定期更新；**<br>
> **规则构成：以[向晚](https://t.me/xiangwanguan)基于[奶思重写合集](https://github.com/fmz200/wool_scripts/blob/main/QuantumultX/rewrite/chongxie.txt)与[DarkWang重写合集](https://raw.githubusercontent.com/zirawell/R-Store/main/Rule/QuanX/Adblock/All/filter/allAdBlock.list)定制，并持续手动维护的[重写合集](https://github.com/XiangwanGuan/Shadowrocket/blob/main/Rewrite/RewriteBuild.conf)为基础，融合了[Bilibili](https://github.com/XiangwanGuan/Shadowrocket/blob/main/Rewrite/Bilibili.conf)[YouTube](https://github.com/XiangwanGuan/Shadowrocket/blob/main/Rewrite/YouTube.conf)、[高德地图](https://github.com/XiangwanGuan/Shadowrocket/blob/main/Rewrite/Amap.js)、[一汽大众](https://github.com/XiangwanGuan/Shadowrocket/blob/main/Rewrite/FAWVW.js)的专用规则；**<br>
> **所有[远程资源](https://github.com/XiangwanGuan/Shadowrocket/blob/main/Rewrite/JavaScriptCheck.md)由[GitHub Actions](https://github.com/XiangwanGuan/Shadowrocket/blob/main/.github/workflows/Update%20RewriteFiles.yml)每日自动备份&监测，所有规则指向的资源已重定向至[当前仓库](https://github.com/XiangwanGuan/Shadowrocket/tree/main/Rewrite/JavaScript)；**<br>
> 使用办法：使用安装Shadowrocket的手机访问此页面，点击[安装链接](https://lowertop.github.io/Shadowrocket-First/redirect.html?url=shadowrocket://install?module=https://xiangwanguan.github.io/Shadowrocket/Module.sgmodule)，一键跳转安装；<br>
> 使用须知：使用融合模块，**必须开启MitM**，教程参考下方的[推荐设置](#推荐设置)；<br>
> 特别说明：使用融合模块，**默认禁用QUIC协议**，请自行评估影响；<br>
> **特别警告：融合模块不做“解锁”功能，请支持开发者！如本项目侵犯了您的利益，请提交Issues进行移除，谢谢！**<br>

---

### [推荐设置](#推荐设置)<br>
#### MitM&证书模块<br>
> 如需使用`融合模块`来净化应用，则**必须开启MitM**，否则模块将不能正常工作；<br>
> **建议添加证书模块**，避免因配置变化导致证书失效；<br>
> 证书信任之后，**请勿在设置中移除证书**，否则MitM将会失效；<br>
> 证书模块添加成功后，“HTTPS解密”开关将不再重要，默认开启（模块的优先级高于配置）；<br>

> 证书模块制作办法：<br>
> 配置 > 点击配置文件的 ⓘ 图标 > HTTPS 解密 > 证书 > 生成新的 CA 证书 > 安装证书；<br>
> 同一iCloud的多设备用户，另一台设备请选择“粘贴”，请勿重新生成新的证书，否则上一证书将会失效；<br>
> 系统设置 > 已下载描述文件 > 安装；<br>
> 系统设置 > 通用 > 关于本机 > 证书信任设置 > 启用此证书的根证书完全信任；<br>
> 打开Shadowrocket，点击「已安装证书的配置文件」后面的 ⓘ 图标 > HTTPS 解密 > 证书后面的 ⓘ 图标 > 复制；<br>
> 配置 > 模块 > 新建模块，粘贴并自行修改以下内容：<br>

> ```ini
> #!name = 证书模块
> [MITM]
> enable = true
>
> # 确认"ca-passphrase="后面填写的「已安装证书的配置文件」的证书密码是否正确，Shadowrocket是默认密码；
> ca-passphrase = Shadowrocket
>
> # 须在"ca-p12="后面粘贴证书内容；
> ca-p12 = 
> ```

> 按说明确认`证书密码`和填写`证书内容`，保存即可；<br>

#### 软件配置<br>
> 首页-全局路由：
选择`配置`；<br>
> 设置-按需求连接：
开启`始终开启`；<br>
> 设置-代理：
代理类型选择`None`，代理地址选择`198.18.0.3`；<br>
> 设置-配置：
开启`自动后台更新`，间隔选择`7`；**（如有自定义配置，请勿开启！）**<br>
> 设置-订阅：
开启`自动后台更新`，间隔选择`24`；<br>
> 设置-GeoLite2数据库：
开启`自动后台更新`，间隔选择`7`；<br>
> 设置-GeoLite2数据库：
拷贝下载链接：[Country](https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-only-cn-private.mmdb) & [ASN](https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-asn.mmdb)，粘贴至对应的`URL`位置，点击`更新`；<br>
> 设置-温和策略机制：
选择`开启`；<br>
> 设置-排除路由0.0.0.0/31：
选择`关闭`；<br>
> 更多使用说明，可参阅：[Shadowrocket使用手册](https://github.com/LOWERTOP/Shadowrocket)

---

### [特别鸣谢](#特别鸣谢)<br>
[*@app2smile*](https://github.com/app2smile/rules)
[*@blackmatrix7*](https://github.com/blackmatrix7)
[*@ddgksf2013*](https://github.com/ddgksf2013/ddgksf2013)
[*@fmz200*](https://github.com/fmz200/wool_scripts)
[*@iab0x00*](https://github.com/iab0x00/ProxyRules)
[*@Keywos*](https://github.com/Keywos/rule)
[*@kokoryh*](https://github.com/kokoryh/Sparkle)
[*@LOWERTOP*](https://github.com/LOWERTOP/Shadowrocket-First)
[*@Loyalsoldier*](https://github.com/Loyalsoldier/geoip)
[*@Maasea*](https://github.com/Maasea/sgmodule)
[*@mw418*](https://github.com/mw418/Loon)
[*@NobyDa*](https://github.com/NobyDa/Script)
[*@Sliverkiss*](https://github.com/Sliverkiss/QuantumultX)
[*@ZenmoFeiShi*](https://github.com/ZenmoFeiShi/Qx)
[*@zirawell*](https://github.com/zirawell/R-Store)
[*@zZPiglet*](https://github.com/zZPiglet/Task)<br>

---
