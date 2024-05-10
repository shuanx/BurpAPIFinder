# BurpAPIFinder
![](https://img.shields.io/badge/Author-Shaun-blue)
![](https://img.shields.io/badge/JDK-9+-yellow)
![](https://img.shields.io/badge/捡漏是门艺术-往往有意想不到的成果-red)
> 攻防演练过程中，我们通常会用浏览器访问一些资产，但很多未授权/敏感信息/越权隐匿在已访问接口过html、JS文件等，通过该Burp插件我们可以：  
> 1、发现通过某接口可以进行未授权/越权获取到所有的账号密码、私钥、凭证  
> 2、发现通过某接口可以枚举用户信息、密码修改、用户创建接口  
> 3、发现登陆后台网址  
> 4、发现在html、JS中泄漏账号密码或者云主机的Access Key和SecretKey  
> ...  

![img.png](images/main.png)

## 功能如下
> 如果有更好的建议或者期待使用的，点个免费的Star
- [x] 提取网站的URL链接和解析JS文件中的URL链接
- [x] 前段界面可自行定义敏感关键词、敏感url匹配
- [x] 界面可配置的开启主动接口探测、敏感信息获取
- [x] 集成主流攻防场景敏感信息泄漏的指纹库  
![img.png](images/config.png)
- [x] 集成HaE的敏感信息识别指纹  
![img.png](images/HaE.png)
- [x] 集成APIKit的敏感信息识别指纹  
![img.png](images/APIKit.png)
- [x] 集成sweetPotato的敏感信息识别指纹  
![img.png](images/sweetPotato.png)

## 闲聊/优化/建议/问题反馈群
<img src="images/weixinqun.png" alt="img.png" width="200"/>

## 额外推荐笔者另一个好用的插件 - BurpFingerPrint
GITHUB: https://github.com/shuanx/BurpFingerPrint
该插件为作者精心开发出来, 旨在打造最强免费指纹识别库和弱口令探测库
> 攻击过程中，我们通常会用浏览器访问一些资产，该BurpSuite插件实现被动指纹识别+网站提取链接+OA爆破，可帮助我们发现更多资产。
- [x] 浏览器被动指纹识别，已集成Ehole指纹识别库
- [x] 提取网站的URL链接和解析JS文件中的URL链接后进行指纹识别
- [x] 开界面进行指纹库修改，可导入、导出、重置
- [x] 优化已有指纹库，区分重点指纹和常见指纹，补充部分实战热门漏洞的指纹，方便直接一键getshell
- [x] 优化算法，提升性能、减少内存开销
- [x] 使用sqlite存储扫描结果，放置因BurpSuite意外退出而导致数据丢失
- [ ] 收集github上常见的EXP工具，提起其含有EXP漏洞的指纹，当成重要指纹，一旦页面出现该指纹，就表示有戏有戏
- [ ] 集成弱口令爆破页面和默认场景场景下弱口令爆破功能

## 免责声明

本工具仅作为安全研究交流，请勿用于非法用途。如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，本人将不承担任何法律及连带责任。
