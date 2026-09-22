# Chradare2 中文帮助

radare2 中文帮助插件 manr2:让 `xxx?` 帮助页面在交互终端里直接显示中文。当前在 Termux(R2 5.9.x)上编译运行。

## 效果

原样执行 r2 的帮助命令,再把输出逐行换成中文,不改动 r2 本体功能。示例:

```
[0x00000000]> s?
用法: s [addr]   Seek to address (also for '?')
| s               打印当前地址
| s addr          跳转到该地址
| s- 1            向前跳转 1 个块
| s+ 1            向后跳转 1 个块
```

支持两种触发方式:

1. 自动接管:输入任意 `xxx?` 帮助请求(如 `f?`、`wx?`、`dr?`),输出自动中文化
2. 手动查表:`manr2 <命令名>`(如 `manr2 ag`),对不熟的命令单独查中文说明

## 安装

编译插件并放入 r2 插件目录:

```sh
gcc -fPIC -shared -o $HOME/.local/share/radare2/plugins/core_manr2.so \
  manr2.c \
  -I$PREFIX/include/libr -I$PREFIX/include -L$PREFIX/lib \
  -lr_core -lr_util -Wl,-rpath,$PREFIX/lib
```

启动任意 r2 进程即自动加载,无需配置。可用 `e manr2.auto` 随时开关自动接管。

## 词表规模

- 命令描述(desc)3314 条
- 用法说明(usage)274 条
- 参数说明(args)172 条
- 覆盖 299 个帮助页,全部中文;12+ 常用页回归验证零英文残留
- 二级帮助页(`?e?`、`?$?`、`?@?`、`?&?` 等)均已翻译
- 唯一保留英文的是 `wv?` 页的 `Supported sizes: 1,2,4,8` 数据行

## 已知限制

以下帮助页无法接管,原因是 r2 架构:修饰符(`@ ~ | >`)在命令分发层(`r_core_cmd_subst`)即被消费,到不了插件回调:

- `@?`(可用等价形式 `?@?`,内容已中文)
- `@@?`、`@@@?`(迭代器,内容已包含在 `?@?` 页)
- `~?`、`~??`(grep 过滤器)
- `|?`、`?>?`(管道/重定向,条目已在 `??` 主帮助页中文段)

## 文件

| 文件 | 说明 |
| --- | --- |
| manr2.c | 插件源码:识别帮助请求、执行原命令、逐行翻译重写输出 |
| manr2dict.h | 词表源码(由 genheader.py 从翻译表生成) |

## 词表维护

翻译表(pairs TSV)与生成脚本 genheader.py 在生成机临时目录,不入库。改动流程:在 pairs 表追加词条 → 运行 genheader.py → 重新生成 manr2dict.h → 按上文命令重编插件。

## 关联项目

[官方 Radare2](https://github.com/radareorg/radare2) 是原版工具,本项目仅提供中文帮助层。