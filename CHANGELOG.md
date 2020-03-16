# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Margular/frida-skeleton/compare/v2.4.1...HEAD
[2.4.1]: https://github.com/Margular/frida-skeleton/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/Margular/frida-skeleton/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/Margular/frida-skeleton/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/Margular/frida-skeleton/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/Margular/frida-skeleton/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/Margular/frida-skeleton/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/Margular/frida-skeleton/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/Margular/frida-skeleton/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Margular/frida-skeleton/releases/tag/v1.0.0

