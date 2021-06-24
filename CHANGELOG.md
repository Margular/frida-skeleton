# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.2.3] - 2021-06-24

### Add

* 保存hook脚本的整个内容方便调试和查看

### Changed

* 在调用Trace.javaClassByRegex的时候默认跳过hook系统函数，通常来说我们希望hook的是APP自身的函数。可以通过第二个参数传入true强制hook系统函数

### Fixed

* 修复可能无法退出程序的BUG

## [3.2.2] - 2021-06-17

### Fixed

* 修复frida-server启动之前就attach进程导致报错的BUG


## [3.2.1] - 2021-04-18

### Add

* 新增指定设备hook的功能


## [3.2.0] - 2020-12-24

### Add

* 新增Jav.describeObject API，很方便地打印java对象的函数和字段信息
* 加入星链计划2.0
* 添加logo

### Changed

* 迁移wiki到github
* 主程序帮助界面改为中文

## [3.1.0] - 2020-06-06

### Add

* 新增spawn选项，现在可以根据选项全局spawn模式，或者在项目配置文件里面配置spawn为true
* 新增项目优先级选项，数字越小越优先加载，用于hook有先后关系的场景，默认为0，默认工程为-100，为最优先

### Changed

* 默认工程的bypass代码更新，现在可以根据新老设备自动切换hook脚本，老设备需要自行上传证书到/data/local/tmp/cert-der.crt
* Common.impl函数大改，现在通过指定对象hook而不是字符串

## [3.0.0] - 2020-06-02

### Add

* 新增项目概念，现在可以在projects目录下创建自己的项目
* Javascript函数库新增namespace，每个内置函数库都有了自己的namespace，互不影响

### Changed

* 代码结构变化，Javascript函数库分为内置函数库和用户自定义函数库，scripts下为内置函数库，projects目录下为用户自定义函数库

## [2.5.0] - 2020-05-28

### Add

- 新增spawn模式，使用-s参数激活
- 新增byte[]和hex格式之间的转化，并在implementationWrapper内部自动判断是否是byte[]，如果是则以hex格式输出

### Changed

- 日志输出格式优化，现在会标记是哪个设备的哪个apk打印的
- 下载frida-server的时候显示百分比优化，现在固定xx.xx%的格式
- PortManager在获取随机端口的时候会剔除本机已开启的端口

## [2.4.1] - 2020-03-16

### Changed

- 修复没有-p参数时的找不到iptables的bug
- 取消初始化的时候删除iptables，而在退出时再保证清除
- 修复有的手机调用self.device.kill会报错的问题



## [2.4.0] - 2020-03-14

### Add

- 解决有的设备通过frida.enumerate_devices()无法列出usb设备，改用frida.get_device_manager().add_remote_device()的方式



### Changed

- 添加线程管理器使得子线程能够正常全部退出后再退出主线程



## [2.3.0] - 2020-03-11

### Add

- 优雅地关闭frida-skeleton使其能够在退出的同时自动清除iptables并关闭frida-server以求对设备影响最小
- 解决windows不能通过CTRL+C关闭frida-skeleton的bug



## [2.2.0] - 2019-12-22

### Changed

- 优化日志格式
- 代码架构调整 



## [2.1.1] - 2019-12-21

### Changed

- 使得手机流量能够被捕获



## [2.1.0] - 2019-12-21

### Changed

- 更通用的iptables设置用以重定向TCP流量



## [2.0.0] - 2019-12-20

### Added

- 多彩日志
- 利用iptables和adb实现TCP流量重定向
- 面向对象化
- 捕获异常
- 自动下载/安装/运行frida-server一条龙服务



## [1.1.0] - 2019-12-16

### Added

- 一次性hook多个usb设备



## [1.0.0] - 2019-09-15
### Added
- 通过正则表达式匹配包名
- 自动打印日志
- Frida-Skeleton独有的implementationWrapper更方便地写hook代码
- 自动绕过证书绑定校验
- 内置Java类hook方法
- 内置jni函数hook方法
- 良好的可扩展性

[Unreleased]: https://github.com/Margular/frida-skeleton/compare/v3.2.3...HEAD
[3.2.3]: https://github.com/Margular/frida-skeleton/compare/v3.2.2...v3.2.3
[3.2.2]: https://github.com/Margular/frida-skeleton/compare/v3.2.1...v3.2.2
[3.2.1]: https://github.com/Margular/frida-skeleton/compare/v3.2.0...v3.2.1
[3.2.0]: https://github.com/Margular/frida-skeleton/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/Margular/frida-skeleton/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/Margular/frida-skeleton/compare/v2.5.0...v3.0.0
[2.5.0]: https://github.com/Margular/frida-skeleton/compare/v2.4.1...v2.5.0
[2.4.1]: https://github.com/Margular/frida-skeleton/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/Margular/frida-skeleton/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/Margular/frida-skeleton/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/Margular/frida-skeleton/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/Margular/frida-skeleton/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/Margular/frida-skeleton/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/Margular/frida-skeleton/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/Margular/frida-skeleton/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Margular/frida-skeleton/releases/tag/v1.0.0

