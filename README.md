![ProxyCat](https://socialify.git.ci/honmashironeko/ProxyCat/image?description=1&descriptionEditable=%E4%B8%80%E6%AC%BE%E8%BD%BB%E9%87%8F%E7%BA%A7%E7%9A%84%E4%BC%98%E7%A7%80%E4%BB%A3%E7%90%86%E6%B1%A0%E4%B8%AD%E9%97%B4%E4%BB%B6%EF%BC%8C%E5%AE%9E%E7%8E%B0%E4%BB%A3%E7%90%86%E7%9A%84%E8%87%AA%E5%8A%A8%E8%BD%AE%E6%8D%A2&font=Bitter&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F139044047%3Fv%3D4&name=1&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Dark)

## 项目概述

渗透过程中总是遇到需要隐藏IP地址或者更换IP地址绕过安全设备的情况，但是市面上的隧道代理价格极其昂贵，普遍在20-40元/天，这高昂的费用令人难以接受。但是笔者注意到短效IP其实性价比很高，一个IP只需要几分钱，平均只需要0.5-3元/天。

综上所述，本工具应运而生！目的是在于将持续时间仅有1分钟-60分钟不等的短效IP转变成一个固定IP供其他工具使用，形成代理池服务器，部署一次即可永久使用。

![项目原理图](./assets/202408260021207.png)

## 项目使用

### 安装依赖

工具基于 Python 实现，在使用前请使用以下命令配置依赖：

```bash
pip install -r requirements.txt
# or 推荐使用国内源：
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple/
```

使用 `python` 命令在项目目录运行 `python3 ProxyCat.py -h` 回显如下即配置成功：

```
# python3 ProxyCat.py -h
      |\      _,,,---,,_  by 本间白猫
ZZZzz /,`.-'`'    -.  ;-;;,_
     |,4-  ) )-,_. ,\ (  `'-'
    '---''(_/--'  `-'\_)  ProxyCat

用法: ProxyCat.py [-h] [-p P] [-m M] [-t T]

参数:
  -h, --help  show this help message and exit
  -p P        监听端口
  -m M        代理轮换模式:cycle 表示循环使用,once 表示用完即止
  -t T        代理更换时间(秒),设置为0秒时变成每次请求更换IP
  -up UP      指定账号密码,格式为username:password
  -k          使用 getip 模块获取代理地址
  (默认监听1080端口，默认cycle循环模式，默认60秒更新一次代理，默认账号neko:123456)
```

### ip.txt 手动录入代理地址

按照该格式`socks5://127.0.0.1:7890` or` http://127.0.0.1:7890` 一行一个填入ip.txt文件中：

```ip.txt
socks5://127.0.0.1:7890
http://127.0.0.1:7890
...
```

>  如果您缺少合适的代理地址，恰巧又有几块钱的话可以联系作者（微信公众号：樱花庄的本间白猫），获取多家低价代理购买地址，为作者带来几毛钱的推荐收益~

配置对应参数后即可使用：

```bash
# python3 ProxyCat.py -p 1080 -m cycle -t 180
- 效果：监听1080端口 代理轮换模式为循环使用 每180秒更换到下一个代理地址
```

**演示效果如下**

固定代理地址（默认）：[http://neko:123456@127.0.0.1:1080](http://neko:123456@127.0.0.1:1080/)

如果您是部署在公网，将127.0.0.1替换成您的公网IP即可。

![手动录入代理地址](./assets/202408260020039.png)

### 使用接口自动获取代理地址

工具支持直接调用代理地址获取的API接口，当您指定-k参数时，工具将不再从本地ip.txt中读取代理地址，而是更换为通过执行 **getip.py** 脚本来获取新的代理地址。

此时，您需要将 **getip.py** 内容修改为您自己的接口，格式为 `IP:PORT`，默认为 `http` 协议，如果您要使用 `socks5` ，请手动更改。

```
# python3 ProxyCat.py -k
```

**演示效果如下**

> 此处的运营商可在下方广告区域获取

![接口自动获取代理地址](./assets/202408260020704.png)

## 性能表现

当前经过实际测试，在代理地址服务器性能足够的情况下，能够做到100并发不丢包，基本可以覆盖大部分扫描和渗透测试。

![性能表现](./assets/202408260020611.png)

## 免责申明

- 如果您下载、安装、使用、修改本工具及相关代码，即表明您信任本工具
- 在使用本工具时造成对您自己或他人任何形式的损失和伤害，我们不承担任何责任
- 如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任
- 请您务必审慎阅读、充分理解各条款内容，特别是免除或者限制责任的条款，并选择接受或不接受
- 除非您已阅读并接受本协议所有条款，否则您无权下载、安装或使用本工具
- 您的下载、安装、使用等行为即视为您已阅读并同意上述协议的约束

## 更新日志

**2024/08/25**

- 读取ip.txt时自动跳过空行
- httpx更换为并发池，提高性能
- 增加缓冲字典，相同站点降低延迟
- 每次请求更换IP逻辑修改为，随机选择代理
- 采用更加高效的结构和算法，优化请求处理逻辑

**2024/08/24**

- 采用异步方案提高并发能力和减少超时
- 重复代码封装提高代码复用性

**2024/08/23**

- 修改并发逻辑
- 增加身份鉴别功能
- 增加IP获取接口，永久更换IP
- 增加每次请求更换IP功能

## 开发计划

- [x] 增加代理服务器身份鉴别功能，保证在公网使用过程中不被恶意盗用

- [x] 增加每次请求更换IP功能

- [x] 增加静态代理自动获取更新模块，从而永久运行

- [ ] 增加负载均衡模式，同时使用大量代理地址发送，从而有效提高并发效率

- [ ] 增加版本检测功能

  如果您有好的idea，或者使用过程中遇到的bug，都请辛苦您添加作者联系方式进行反馈！

  微信公众号：樱花庄的本间白猫

## 鸣谢

本排名不分先后，感谢为本项目提供帮助的师傅们。

[AabyssZG (曾哥)](https://github.com/AabyssZG)

[ProbiusOfficial (探姬)](https://github.com/ProbiusOfficial)

## 赞助开源

开源不易，如果您觉得工具不错，或许可以试着赞助一下作者的开发哦~

![ced79e6745867bd51b1eddfb17cb5702](./assets/202408260020820.png)

## 代理推荐

- [第一家代理池购买点击这里跳转](https://www.juliangip.com/user/reg?inviteCode=1033745) 
- [第二家代理池购买点击这里跳转](https://www.kuaidaili.com/?ref=pglfmm887dmw)
- [各大运营商流量卡](https://172.lot-ml.com/ProductEn/Index/0b7c9adef5e9648f)

[![Star History Chart](https://api.star-history.com/svg?repos=honmashironeko/ProxyCat&type=Date)](https://star-history.com/#honmashironeko/ProxyCat&Date)

