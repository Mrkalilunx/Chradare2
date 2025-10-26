/* radare - LGPL - Copyright 2009-2025 - pancake */

#if R_INCLUDE_BEGIN

static RCoreHelpMessage help_msg_question_t = {
	"用法: ?t[0,1] [cmd]", "", "",
	"?t", " pd 32", "显示运行'pd 32'所需时间",
	"?t0", "", "选择第一个可视化标签页",
	"?t1", "", "选择下一个可视化标签页",
	NULL
};

static RCoreHelpMessage help_msg_at = {
	"用法: [.:\"][#]<cmd>[*] [`cmd`] [@ addr] [~grep] [|syscmd] [>[>]file]", "", "",
	"0", "", "'s 0'的别名",
	"0x", "addr", "'s 0x..'的别名",
	"#", "cmd", "如果#是数字，则重复命令#次",
	"/*", "", "开始多行注释",
	"*/", "", "结束多行注释",
	".", "cmd", "将命令输出作为r2脚本执行",
	".:", "8080", "在8080端口等待命令",
	".!", "rabin2 -re $FILE", "运行命令输出作为r2脚本",
	":", "cmd", "运行io命令（同=!）",
	"-", "[?]", "s-的别名，负向相对跳转和脚本编辑器",
	"+", "[?]", "s+的别名，作为相对跳转",
	"*", "", "以r2脚本格式输出命令结果",
	"j", "", "以JSON格式输出命令结果",
	"~", "?", "统计行数（类似wc -l）",
	"~", "??", "显示内部grep帮助",
	"~", "..", "内部less",
	"~", "{}", "JSON缩进",
	"~", "<>", "XML缩进",
	"~", "<100", "控制台缓冲区的ASCII艺术缩放",
	"~", "{}..", "JSON缩进并less",
	"~", "word", "grep匹配word的行",
	"~", "!word", "grep不匹配word的行",
	"~", "word[2]", "grep匹配word的行的第3列",
	"~", "word:3[0]", "从第4行匹配word的行的第1列开始grep",
	"@", " 0x1024", "临时跳转到此地址",
	"@", " [addr]!blocksize", "临时设置新块大小",
	"@..", "addr", "临时部分地址跳转（见s..）",
	"@!", "blocksize", "临时更改块大小",
	"@{", "from to}", "为支持范围的命令临时设置起始和结束",
	"@%", "env[=value]", "使用环境变量值作为临时跳转地址",
	"@a:", "arch[:bits]", "临时设置架构和位数",
	"@b:", "bits", "临时设置asm.bits",
	"@B:", "nth", "临时跳转到当前基本块的第n条指令",
	"@c:", "cmd", "跳转到给定命令打印的地址",
	"@e:", "k=v,k=v", "临时更改eval变量",
	"@f:", "file", "临时用文件内容替换块",
	"@F:", "flagspace", "临时更改标志空间",
	"@i:", "nth.op", "临时跳转到第N条相对指令",
	"@k:", "k", "临时跳转到sdb键k的值",
	"@o:", "fd", "临时切换到另一个文件描述符",
	"@r:", "reg", "临时跳转到寄存器值",
	"@s:", "string", "同上但从字符串",
	"@v:", "value", "将当前偏移修改为自定义值",
	"@x:", "909192", "从十六进制对字符串",
	"@xc:", "p8 32", "从命令输出的十六进制对",
	"@xf:", "foo.hex", "从给定文件加载十六进制对字符串到当前块",
	"@@=", "1 2 3", "在偏移1、2、3处运行前一个命令",
	"@@==", "foo bar", "在每次迭代时附加单词运行前一个命令",
	"@@", " hit*", "在每个匹配'hit*'的标志上运行命令",
	"@@", "[?][ktfb..]", "显示迭代器操作符帮助",
	"@@@", "[?] [type]", "在每个[type]上运行命令",
	">", "file", "将命令输出管道到文件",
	">>", "file", "追加到文件",
	"H>", "file", "将命令的HTML输出管道到文件",
	"H>>", "file", "将命令的HTML输出追加到文件",
	"`", "pdi~push:0[0]`", "用命令输出替换行内内容",
	"|", "cmd", "将输出管道到命令",
	NULL
};

static RCoreHelpMessage help_msg_at_at = {
	"@@", "", " # 遍历迭代器命令:",
	"x", " @@ sym.*", "在当前标志空间中对所有匹配'sym.'的标志运行'x'",
	"x", " @@.file", "对文件中指定的偏移运行'x'",
	"x", " @@/x 9090", "临时设置cmd.hit以在每个搜索结果上运行命令",
	"x", " @@=`pdf~call[0]`", "在当前函数的每个调用偏移处运行'x'",
	"x", " @@=off1 off2 ..", "手动偏移列表",
	"x", " @@b", "在当前函数的所有基本块上运行'x'",
	"x", " @@c:cmd", "同@@=``但不使用反引号",
	"x", " @@dbt[abs]", "在每个回溯地址、bp或sp上运行'x'命令",
	"x", " @@f", "在所有函数上运行'x'",
	"x", " @@f:write", "在所有名称匹配write的函数上运行'x'",
	"x", " @@F", "@@c:afla的别名 - 反向递归函数列表",
	"x", " @@i", "在当前函数的所有指令上运行'x'",
	"x", " @@iS", "在所有节上运行'x'并调整块大小",
	"x", " @@k sdbquery", "在该sdb查询返回的所有偏移上运行'x'",
	"x", " @@s:from to step", "在从from到to的所有偏移上运行'x'，步长为step",
	"x", " @@t", "在所有线程上运行'x'",
	NULL
};

static RCoreHelpMessage help_msg_single_quote = {
	"'", "# 运行命令而不评估任何特殊字符", "",
	"'", "?e hello @ world", "打印`?e`之后的所有内容",
	"'", "0x123'?v $$", "在0x123偏移处运行'?v $$'命令",
	"'", "@entry0'?v $$", "同'0x但支持非数字偏移",
	NULL
};

static RCoreHelpMessage help_msg_at_at_at = {
	"@@@", "", " # 遍历偏移+大小迭代器命令:",
	"x", " @@@=", "[addr] [size] ([addr] [size] ...)",
	"x", " @@@b", "当前函数的基本块",
	"x", " @@@C:cmd", "匹配的注释",
	"x", " @@@c:cmd", "同@@@=`cmd`，但不使用反引号",
	"x", " @@@e", "入口点",
	"x", " @@@E", "导出",
	"x", " @@@f", "标志",
	"x", " @@@F", "函数",
	"x", " @@@F:glob", "匹配glob表达式的函数",
	"x", " @@@f:hit*", "匹配glob表达式的标志",
	"x", " @@@i", "导入",
	"x", " @@@M", "调试映射",
	"x", " @@@m", "IO映射",
	"x", " @@@r", "寄存器",
	"x", " @@@R", "重定位",
	"x", " @@@S", "节",
	"x", " @@@s", "符号",
	"x", " @@@SS", "段",
	"x", " @@@t", "线程",
	"x", " @@@z", "字符串",
	NULL
};

static ut32 vernum(const char *s) {
	char *a = strdup (s);
	a = r_str_replace (a, ".", "0", 1);
	char *dash = strchr (a, '-');
	if (dash) {
		*dash = 0;
	}
	ut32 res = atoi (a);
	free (a);
	return res;
}

static RCoreHelpMessage help_msg_percent = {
	"Usage:", "%[name[=value]]", "在环境中设置每个NAME为VALUE",
	"%", "", "列出所有环境变量",
	"%", "*", "以r2命令格式显示环境变量",
	"%", "j", "以JSON格式显示环境变量",
	"%", "SHELL", "打印SHELL值",
	"%", "TMPDIR=/tmp", "设置TMPDIR值为\"/tmp\"",
	NULL
};

static RCoreHelpMessage help_msg_env = {
	"\nEnvironment:", "", "",
	"R2_FILE", "", "文件名",
	"R2_OFFSET", "", "10进制偏移64位值",
	"R2_BYTES", "", "当前块中的字节",
	"R2_XOFFSET", "", "同上，但为16进制",
	"R2_BSIZE", "", "块大小",
	"R2_ENDIAN", "", "'big'或'little'",
	"R2_IOVA", "", "是否使用虚拟地址",
	"R2_DEBUG", "", "是否启用调试模式",
	"R2_BLOCK", "", "当前块转储到临时文件",
	"R2_SIZE", "", "文件大小",
	"R2_ARCH", "", "asm.arch的值",
	"R2_BITS", "", "架构寄存器大小",
	"RABIN2_LANG", "", "反混淆时假设的语言",
	"RABIN2_DEMANGLE", "", "是否反混淆",
	"RABIN2_PDBSERVER", "", "pdb服务器",
	NULL
};

static RCoreHelpMessage help_msg_exclamation = {
	"Usage:", "!<cmd>", "  在系统中运行给定命令",
	"!", "", "列出shell历史中的所有命令",
	"!", "ls", "在shell中执行'ls'",
	"!*", "r2p x", "通过r2pipe在当前会话中运行r2命令",
	"!.", "", "将命令历史保存到历史文件",
	"!!", "", "列出当前会话中使用的命令",
	"!!", "ls~txt", "打印'ls'输出并grep'txt'",
	"!!!", "cmd [args|$type]", "添加自动完成值",
	"!!!-", "cmd [args]", "移除自动完成值",
	".!", "rabin2 -rpsei ${FILE}", "将每行输出作为r2命令运行",
	"!", "echo $R2_SIZE", "显示文件大小",
	"!-", "", "清除当前会话的历史",
	"!-*", "", "清除并保存空历史日志",
	"!=!", "", "启用远程命令模式",
	"=!=", "", "禁用远程命令模式",
	NULL
};

static RCoreHelpMessage help_msg_root = {
	"%var", "=value", "'env'命令的别名",
	"\"", "[?][\"..|..\"]", "引用以避免评估特殊字符",
	"'", "[...]", "运行命令而不评估任何特殊字符",
	"*", "[?] off[=[0x]value]", "指针读/写数据/值",
	"(macro arg0 arg1)",  "", "管理脚本宏",
	".", "[?] [-|(m)|f|!sh|cmd]", "定义宏或加载r2、cparse或rlang文件",
	",", "[?] [/jhr]", "从文件创建和查询或过滤数据表",
	":", "cmd", "运行io命令",
	"-", "[?]", "打开编辑器并运行保存文档中的r2命令",
	"_", "[?]", "打印最后输出",
	"=", "[?] [cmd]", "提交或监听远程命令",
	"<", "[str]", "使用给定转义字符串馈送stdin",
	"/", "[?]", "搜索字节、正则表达式、模式等",
	"!", "[?] [cmd]", "在系统中运行给定命令",
	"#", "[?] !lang [..]", "运行rlang脚本的Hashbang",
	"{", "[?] ...}", "使用json语法运行r2pipe2命令",
	"a", "[?]", "分析命令",
	"b", "[?]", "显示或更改块大小",
	"c", "[?] [arg]", "与给定数据比较块",
	"C", "[?]", "代码元数据",
	"d", "[?]", "调试器命令",
	"e", "[?] [a[=b]]", "列出/获取/设置可评估配置变量",
	"f", "[?] [name][sz][at]", "在当前地址添加标志",
	"g", "[?] [arg]", "使用r_egg生成shellcode",
	"i", "[?] [file]", "从r_bin获取关于打开文件的信息",
	"k", "[?] [query]", "评估sdb查询",
	"l", "[?] [filepattern]", "列出文件和目录",
	"L", "[?] [-] [plugin]", "列出、卸载加载r2插件",
	"m", "[?]", "挂载文件系统并检查其内容",
	"o", "[?] [file] ([addr])", "在可选地址打开文件",
	"p", "[?] [len]", "以格式和长度打印当前块",
	"P", "[?]", "项目管理工具",
	"q", "[?] [ret]", "以返回值退出程序",
	"r", "[?] [len]", "调整文件大小",
	"s", "[?] [addr]", "跳转到给定地址",
	"t", "[?]", "类型、noreturn、签名、C解析器等",
	"T", "[?] [-] [num|msg]", "文本日志工具",
	"u", "[?]", "撤销跳转/写入",
	"v", "", "面板模式",
	"V", "", "可视化模式",
	"w", "[?] [str]", "多重写入操作",
	"x", "[?] [len]", "'px'的别名",
	"y", "[?] [len] [[[@]addr", "从/到内存复制/粘贴字节",
	"z", "[?]", "签名管理",
	"?[??]", "[expr]", "帮助或评估数学表达式",
	"?$?", "", "显示可用的'$'变量和别名",
	"?@?", "", "'@'（跳转）、'~'（grep）的杂项帮助",
	"?>?", "", "输出重定向",
	"?|?", "", "'|'（管道）帮助",
	NULL
};

static RCoreHelpMessage help_msg_question_i = {
	"用法: ?e[=bdgnpst] arg", "打印/回显内容", "",
	"?i", " ([prompt])", "询问用户并将文本保存到剪贴板",
	"?ie", " [msg]", "同?i，但打印输出，适用于单行命令",
	"?iy", " [question]", "是/否对话框，默认为是",
	"?if", " [math-expr]", "评估数学表达式，如果结果为零则返回true",
	"?in", " [question]", "是/否对话框，默认否",
	"?im", " [msg]", "类似?ie，但使用RCons.message",
	"?ik", "", "按任意键",
	"?ip", " ([path])", "交互式HUD模式在给定路径中查找文件",
	"?iu", " (ui-expr)", "使用用户界面表达式输入",
	NULL
};

static RCoreHelpMessage help_msg_question_e = {
	"用法: ?e[=bdgnpst] arg", "打印/回显内容", "",
	"?e", "", "带换行符的回显消息",
	"?e:", "base64text", "解码给定的base64文本并通过rcons显示",
	"?e=", " 32", "进度条显示32%",
	"?ea", " text", "ASCII艺术回显",
	"?eb", " 10 20 30", "比例分段条",
	"?ed", " 1", "在给定动画帧绘制3D ASCII甜甜圈",
	"?ee", " msg", "标准错误消息",
	"?ef", " text", "用细ASCII艺术框回显文本",
	"?eg", " 10 20", "将光标移动到第10列第20行",
	"?ei", " msg", "R_LOG_INFO消息",
	"?em", " 10 20,ten two", "用给定值绘制ASCII艺术树状图",
	"?en", " nonl", "回显消息不带结尾换行符",
	"?ep", " 10 20,ten twe", "渲染饼图",
	"?es", " msg", "使用文本转语音程序朗读消息",
	"?et", " msg", "更改终端标题",
	NULL
};

static RCoreHelpMessage help_msg_question = {
	"用法: ?[?[?]] expression", "", "",
	"?_", " hudfile", "使用给定文件加载HUD菜单",
	"??", "", "显示?命令的帮助",
	"?'", "", "显示单引号帮助",
	"?", " eip-0x804800", "显示此数学表达式的所有表示结果",
	"?=", " eip-0x804800", "用操作结果更新$?返回码",
	"?==", " x86 `e asm.arch`", "比较两个字符串",
	"?$", "", "显示所有变量的值",
	"?a", "", "显示ASCII表",
	"?B", " [elem]", "显示范围边界",
	"?b", " [num]", "显示数字的二进制值",
	"?b64[-]", " [str]", "base64编码/解码",
	"?btw", " num|expr num|expr num|expr", "返回a <= b <= c的布尔值",
	"?d", " [num]", "将给定数字作为小端和大端双字反汇编",
	"?e", "[=bdgnpst] arg", "回显消息、条形图、饼图等",
	"?eq", " [cmd]", "如果$? == 0则运行cmd",
	"?f", " [num] [str]", "将数字的每个位映射为标志字符串索引",
	"?F", "", "刷新控制台输出",
	"?ge", " [cmd]", "如果$? > 0则运行cmd",
	"?h", " [str]", "计算给定字符串的哈希值",
	"?i", "[?] arg", "提示输入数字或是/否/消息/按键/路径并存储在$$?",
	"?j", " arg", "同'? num'但以JSON格式",
	"?l", "[q] str", "返回字符串长度",
	"?le", " [cmd]", "如果$? < 0则运行cmd",
	"?ne", " [cmd]", "如果$? != 0则运行cmd",
	"?o", " num", "获取八进制值",
	"?P", " paddr", "获取给定物理地址的虚拟地址",
	"?p", " vaddr", "获取给定虚拟地址的物理地址",
	"?q", " num|expr", "计算表达式，静默模式",
	"?r", " [from] [to]", "在from-to之间生成随机数",
	"?s", " from to step", "从from到to的数字序列，步长为step",
	"?t", " cmd", "返回运行命令所需的时间",
	"?T", "", "显示加载时间",
	"?u", " num", "获取人类可读单位的值",
	"?v", " num|expr", "显示数学表达式的十六进制值",
	"?V", "", "显示r_core的库版本",
	"?vi", "[1248] num|expr", "显示数学表达式的十进制值",
	"?vx", " num|expr", "显示8位十六进制填充",
	"?w", " addr", "显示此地址内容",
	"?X", " num|expr", "返回数学表达式的十六进制值",
	"?x", " str", "返回数字或字符串的十六进制对",
	"?x", "-hexst", "将十六进制对转换为带换行符的原始字符串",
	"?x", "+num", "类似?v，但以十六进制对显示",
	"[cmd]?*", "", "递归显示给定cmd的帮助",
	NULL
};

static RCoreHelpMessage help_msg_question_v = {
	"用法: ?v [$.]", "", "",
	"flag", "", "标志的偏移",
	"$", "{ev}", "获取eval配置变量的值",
	"$alias", "=value", "别名命令",
	"$", "[addr:size]", "获取eval配置变量的值",
	"$$", "", "当前位置",
	"$$c", "", "相对于当前偏移的光标位置",
	"$$$", "", "当前非临时虚拟跳转",
	"$$$c", "", "光标+当前非临时虚拟跳转",
	"$?", "", "最后比较值",
	"$b", "", "块大小",
	"$k", "{kv}", "获取sdb查询键的值",

	"$in", ":{n}", "第n条向前指令的地址",
	"$ip", ":{n}", "第n条向后指令的地址",
	"$is", "[:{n}]", "指令大小",
	"$ij", "", "跳转地址",
	"$ie", "", "1表示块结束，否则0",
	"$if", "", "跳转失败地址",
	"$ir", "", "指令引用指针值",
	"$iv", "", "操作码立即值",

	"$f", "[:{name}]", "当前地址或给定名称的标志地址",
	"$fs", "[:{name}]", "标志大小",
	"$fe", "[:{name}]", "标志结束",
	"$fd", "[:{name}]", "标志增量",

	"$S", "[:{name}]", "节偏移",
	"$SS", "[:{name}]", "节大小",
	"$SB", "[:{name}]", "节开始",
	"$SD", "[:{name}]", "当前偏移与节开始的距离",
	"$SE", "[:{name}]", "节结束地址",

	"$B", "", "基地址",
	"$c", "", "获取终端宽度",
	"$Cn", "", "获取函数的第n次调用",
	"$D", "", "当前调试映射基地址",
	"$DA", "", "同dbg.baddr，程序基地址",
	"$DB", "", "$D的别名",
	"$DS", "", "当前调试映射大小",
	"$DD", "", "当前调试映射距离",

	"$BB", "", "基本块开始",
	"$BE", "", "基本块结束",
	"$Bj", "", "基本块跳转地址",
	"$Bf", "", "基本块失败/回退地址",
	"$Bi", "", "基本块指令",
	"$BS", "", "基本块大小",
	"$BC", "", "此块的案例数",
	"$BC", ":#", "第n个案例的地址",

	"$F", "", "同$FB",
	"$FB", "", "函数开始",
	"$FE", "", "函数结束",
	"$FI", "", "函数指令",
	"$Fs", "", "线性函数大小",
	"$FS", "", "基本块总大小",
	"$Fr", "", "获取函数中第n个数据引用",
	"$Fc", ":nth", "第n次调用",
	"$Fj", ":nth", "第n次跳转",
	"$Fx", ":nth", "第n次交叉引用",

	"$M", "", "映射地址",
	"$ME", "", "映射结束地址",
	"$MB", "", "$M的别名",
	"$MD", "", "当前偏移与映射地址的映射距离",
	"$MM", "", "映射基地址",
	"$MS", "", "映射大小",

	"$o", "", "当前位置",
	"$p", "", "getpid()",
	"$P", "", "子进程PID",
	"$r", "", "获取控制台高度",
	"$r", "{reg}", "获取命名寄存器的值",
	"$s", "", "文件大小",
	"$w", "", "获取字大小",
	"RNum", "", "可在数学表达式中使用的$变量",
	NULL
};

static RCoreHelpMessage help_msg_question_V = {
	"用法: ?V[jq]", "", "",
	"?V", "", "显示版本信息",
	"?V0", "", "显示主版本",
	"?V1", "", "显示次版本",
	"?V2", "", "显示补丁版本",
	"?Vn", "", "显示数字版本",
	"?Vc", "", "显示数字版本",
	"?Vj", "", "同上但以JSON格式",
	"?Vq", "", "静默模式，仅显示版本号",
	NULL
};

static RCoreHelpMessage help_msg_greater_sign = {
	"Usage:", "[cmd]>[file]", "将'cmd'输出重定向到'file'",
	"[cmd] > [file]", "", "将'cmd'的STDOUT重定向到'file'",
	"[cmd] > $alias", "", "将命令输出保存为别名",
	"[cmd] H> [file]", "", "将'cmd'的HTML输出重定向到'file'",
	"[cmd] 2> [file]", "", "将'cmd'的STDERR重定向到'file'",
	"[cmd] 2> "R_SYS_DEVNULL, "", "忽略'cmd'的STDERR输出",
	NULL
};

static RCoreHelpMessage help_msg_intro = {
	"用法: [.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...", "", "",
	"在任何字符命令后附加'?'获取详细帮助", "", "",
	"前缀数字重复命令N次", "", "",
	NULL
};

static void cmd_help_exclamation(RCore *core) {
	r_core_cmd_help (core, help_msg_exclamation);
	r_core_cmd_help (core, help_msg_env);
}

static void cmd_help_percent(RCore *core) {
	r_core_cmd_help (core, help_msg_percent);
	r_core_cmd_help (core, help_msg_env);
}

static const char* findBreakChar(const char *s) {
	while (*s) {
		if (!r_name_validate_char (*s)) {
			break;
		}
		s++;
	}
	return s;
}

// XXX This is an experimental test and must be implemented in RCons directly
static void colormessage(RCore *core, const char *msg) {
	size_t msglen = strlen (msg);
	RCons *cons = core->cons;
	const char *pad = r_str_pad (' ', msglen + 5);
	r_cons_gotoxy (cons, 10, 10); r_cons_printf (cons, Color_BGBLUE"%s", pad);
	r_cons_gotoxy (cons, 10, 11); r_cons_printf (cons, Color_BGBLUE"%s", pad);
	r_cons_gotoxy (cons, 10, 12); r_cons_printf (cons, Color_BGBLUE"%s", pad);
	r_cons_gotoxy (cons, 12, 11); r_cons_printf (cons, Color_BGBLUE""Color_WHITE"%s", msg);
	r_cons_gotoxy (cons, 0, 0);
	r_cons_printf (cons, Color_RESET);
}

static char *filterFlags(RCore *core, const char *msg) {
	const char *dollar, *end;
	char *word, *buf = NULL;
	for (;;) {
		dollar = strchr (msg, '$');
		if (!dollar) {
			break;
		}
		buf = r_str_appendlen (buf, msg, dollar-msg);
		if (dollar[1] == '{') {
			// find }
			end = strchr (dollar + 2, '}');
			if (end) {
				word = r_str_ndup (dollar + 2, end - dollar - 2);
				end++;
			} else {
				msg = dollar + 1;
				buf = r_str_append (buf, "$");
				continue;
			}
		} else if (dollar[1] == '(') {
			msg = dollar + 1;
			buf = r_str_append (buf, "$");
			continue;
		} else {
			end = findBreakChar (dollar + 1);
			if (!end) {
				end = dollar + strlen (dollar);
			}
			word = r_str_ndup (dollar + 1, end - dollar - 1);
		}
		if (end && word) {
			ut64 val = r_num_math (core->num, word);
			r_strf_var (num, 32, "0x%"PFMT64x, val);
			buf = r_str_append (buf, num);
			msg = end;
		} else {
			break;
		}
		free (word);
	}
	buf = r_str_append (buf, msg);
	return buf;
}


#include "clippy.inc.c"
#include "visual_riu.inc.c"

const char iuhelp[] =
"用法: ?iu fieldname(type,command,value)\n"
"  Types: string, button, title, run\n"
"Examples:\n"
"'?iu name(string,?i;yp,test) addr(string,f~...) ok(button) cancel(button)\n"
"'?iu addr(string,f~...) hexdump(run,x 32@k:riu.addr) ok(button)\n"
"Values for every field are saved in the global SdbKv database (see `k` command)\n";

static int cmd_qiu(RCore *core, const char *input) {
	if (!*input || *input == '?') {
		r_cons_print (core->cons, iuhelp);
		return 0;
	}
	RIU *riu = riu_new (core, input);
	do {
		riu_render (riu);
	} while (riu_input (riu));
	riu_free (riu);
	return 0;
}

static int cmd_help(void *data, const char *input) {
	r_strf_buffer (256);
	RCore *core = (RCore *)data;
	RCons *cons = core->cons;
	RIOMap *map;
	const char *k;
	RListIter *iter;
	char *p, out[128] = {0};
	ut64 n;
	int i;
	RList *tmp;

	switch (input[0]) {
	case ':':
		// show help for ':' command
		r_core_cmd_help_match (core, help_msg_at, ":");
		break;
	case 't': { // "?t"
		switch (input[1]) {
		case '0':
			core->curtab = 0;
			break;
		case '1':
			if (core->curtab < 0) {
				core->curtab = 0;
			}
			core->curtab ++;
			break;
		case '\'':
			{
				struct r_prof_t prof;
				r_prof_start (&prof);
				r_core_cmd_call (core, input + 2);
				r_prof_end (&prof);
				r_core_return_value (core, (ut64)(int)prof.result);
				eprintf ("%lf\n", prof.result);
			}
			break;
		case '"':
			{
				struct r_prof_t prof;
				r_prof_start (&prof);
				if (input[1] == '"') {
					// R2_600 - deprecate '""'
					r_core_cmd_call (core, input + 3);
				} else {
					r_core_cmd (core, input + 1, 0);
				}
				r_prof_end (&prof);
				r_core_return_value (core, (ut64)(int)prof.result);
				eprintf ("%lf\n", prof.result);
			}
			break;
		case ' ':
			{
				struct r_prof_t prof;
				r_prof_start (&prof);
				r_core_cmd (core, input + 1, 0);
				r_prof_end (&prof);
				r_core_return_value (core, (ut64)(int)prof.result);
				r_cons_printf (cons, "%lf\n", prof.result);
				break;
			}
		default:
			r_core_cmd_help (core, help_msg_question_t);
			break;
		}
		break;
		}
	case 'r': // "?r"
		{ // TODO : Add support for 64bit random numbers
		ut64 b = 0;
		ut32 r = UT32_MAX;
		if (input[1]) {
			strncpy (out, input + (input[1] == ' '? 2: 1), sizeof (out)-1);
			p = strchr (out + 1, ' ');
			if (p) {
				*p = 0;
				b = (ut32)r_num_math (core->num, out);
				r = (ut32)r_num_math (core->num, p + 1) - b;
			} else {
				r = (ut32)r_num_math (core->num, out);
			}
		} else {
			r = 0LL;
		}
		if (!r) {
			r = UT32_MAX >> 1;
		}
		ut64 n = (ut64)b + r_num_rand (r);
		r_core_return_value (core, n);
		r_cons_printf (cons, "0x%"PFMT64x"\n", n);
		}
		break;
	case '\'': // "?'"
		r_core_cmd_help (core, help_msg_single_quote);
		break;
	case 'a': // "?a"
		if (input[1] == 'e') {
			r_cons_printf (cons, "%s", r_str_chartable ('e'));
		} else {
			r_cons_printf (cons, "%s", r_str_chartable (0));
		}
		break;
	case 'd':
		{
			RAnalOp aop = {0};
			ut8 data[32];
			ut64 n = r_num_math (core->num, input + 1);
			r_write_le32 (data, n);
			int res = r_anal_op (core->anal, &aop, core->addr, data, sizeof (data), R_ARCH_OP_MASK_DISASM);
			if (res > 0) {
				r_cons_printf (cons, "bedec   %s\n", aop.mnemonic);
			} else {
				r_cons_printf (cons, "bedec   invalid\n");
			}
			r_anal_op_fini (&aop);
			r_write_be32 (data, n);
			res = r_anal_op (core->anal, &aop, core->addr, data, sizeof (data), R_ARCH_OP_MASK_DISASM);
			if (res > 0) {
				r_cons_printf (cons, "ledec   %s\n", aop.mnemonic);
			} else {
				r_cons_printf (cons, "ledec   invalid\n");
			}
			r_anal_op_fini (&aop);
		}
		break;
	case 'b': // "?b"
		if (input[1] == '6' && input[2] == '4') {
			//b64 decoding takes at most strlen(str) * 4
			const int buflen = (strlen (input + 3) * 4) + 1;
			char* buf = calloc (buflen, sizeof (char));
			if (!buf) {
				return false;
			}
			if (input[3] == '-') {
				r_base64_decode ((ut8*)buf, input + 4, -1);
			} else if (input[3] == ' ') {
				r_base64_encode (buf, (const ut8*)input + 4, -1);
			}
			r_cons_println (core->cons, buf);
			free (buf);
		} else if (input[1] == 't' && input[2] == 'w') { // "?btw"
			if (r_num_between (core->num, input + 3) == -1) {
				r_core_cmd_help_match (core, help_msg_question, "?btw");
			}
		} else {
			n = r_num_math (core->num, input + 1);
			r_num_to_bits (out, n);
			r_cons_printf (cons, "%sb\n", out);
		}
		break;
	case 'B': // "?B"
		k = r_str_trim_head_ro (input + 1);
		tmp = r_core_get_boundaries_prot (core, -1, k, "search");
		if (!tmp) {
			return false;
		}
		r_list_foreach (tmp, iter, map) {
			r_cons_printf (cons, "0x%"PFMT64x" 0x%"PFMT64x"\n", r_io_map_begin (map), r_io_map_end (map));
		}
		r_list_free (tmp);
		break;
	case 'h': // "?h"
		if (input[1] == ' ') {
			r_cons_printf (cons, "0x%08x\n", (ut32)r_str_hash (input + 2));
		} else {
			r_core_cmd_help_contains (core, help_msg_question, "?h");
		}
		break;
	case 'F': // "?F"
		r_cons_flush (core->cons);
		break;
	case 'f': // "?f"
		if (input[1] == ' ') {
			char *q, *p = strdup (input + 2);
			if (!p) {
				R_LOG_ERROR ("Cannot strdup");
				return 0;
			}
			q = strchr (p, ' ');
			if (q) {
				*q = 0;
				n = r_num_get (core->num, p);
				r_str_bits (out, (const ut8*)&n, sizeof (n) * 8, q + 1);
				r_cons_println (core->cons, out);
			} else {
				r_core_cmd_help_match (core, help_msg_question, "?f");
			}
			free (p);
		} else {
			r_core_cmd_help_match (core, help_msg_question, "?f");
		}
		break;
	case 'o': // "?o"
		n = r_num_math (core->num, input + 1);
		r_cons_printf (cons, "0%"PFMT64o"\n", n);
		break;
	case 'T': // "?T"
		if (input[1] == 'j') {
			PJ *pj = r_core_pj_new (core);
			pj_o (pj);
			pj_kn (pj, "plug.init", core->times->loadlibs_init_time);
			pj_kn (pj, "plug.load", core->times->loadlibs_time);
			pj_kn (pj, "file.load", core->times->file_open_time);
			pj_kn (pj, "file.anal", core->times->file_anal_time);
			pj_end (pj);
			char *s = pj_drain (pj);
			r_cons_printf (cons, "%s\n", s);
			free (s);
		} else {
			r_cons_printf (cons, "plug.init = %"PFMT64d"\n"
				"plug.load = %"PFMT64d"\n"
				"file.load = %"PFMT64d"\n"
				"file.anal = %"PFMT64d"\n",
				core->times->loadlibs_init_time,
				core->times->loadlibs_time,
				core->times->file_open_time,
				core->times->file_anal_time);
		}
		break;
	case 'u': // "?u"
		{
			char unit[8];
			n = r_num_math (core->num, input + 1);
			r_num_units (unit, sizeof (unit), n);
			r_cons_println (core->cons, unit);
		}
		break;
	case 'j': // "?j"
	case ' ': // "? "
		{
			char unit[8];
			double d;
			float f;
			char * const inputs = strdup (input + 1);
			RList *list = r_num_str_split_list (inputs);
			const int list_len = r_list_length (list);
			PJ *pj = NULL;
			if (*input ==  'j') {
				pj = r_core_pj_new (core);
				pj_o (pj);
			}
			const int segbas = core->rasm->config->segbas;
			const int seggrn = core->rasm->config->seggrn;
			for (i = 0; i < list_len; i++) {
				const char *str = r_list_pop_head (list);
				if (!*str) {
					continue;
				}
				const char *err = NULL;
				n = r_num_math_err (core->num, str, &err);
				if (core->num->dbz) {
					R_LOG_ERROR ("Division by Zero");
				}
				if (err) {
					R_LOG_ERROR (err);
					continue;
				}
				char *asnum  = r_num_as_string (NULL, n, false);

				ut32 s = 0, a = 0;
				r_num_segaddr (n, segbas, seggrn, &s, &a);
				r_num_units (unit, sizeof (unit), n);
				if (*input ==  'j') {
					pj_ks (pj, "int32", r_strf ("%d", (st32)(n & UT32_MAX)));
					pj_ks (pj, "uint32", r_strf ("%u", (ut32)n));
					pj_ks (pj, "int64", r_strf ("%"PFMT64d, (st64)n));
					pj_ks (pj, "uint64", r_strf ("%"PFMT64u, (ut64)n));
					pj_ks (pj, "hex", r_strf ("0x%08"PFMT64x, n));
					pj_ks (pj, "octal", r_strf ("0%"PFMT64o, n));
					pj_ks (pj, "unit", unit);
					pj_ks (pj, "segment", r_strf ("%04x:%04x", s, a));
				} else {
					if (n >> 32) {
						r_cons_printf (cons, "int64   %"PFMT64d"\n", (st64)n);
						r_cons_printf (cons, "uint64  %"PFMT64u"\n", (ut64)n);
					} else {
						r_cons_printf (cons, "int32   %d\n", (st32)n);
						r_cons_printf (cons, "uint32  %u\n", (ut32)n);
					}
					r_cons_printf (cons, "hex     0x%"PFMT64x"\n", n);
					r_cons_printf (cons, "octal   0%"PFMT64o"\n", n);
					r_cons_printf (cons, "unit    %s\n", unit);
					r_cons_printf (cons, "segment %04x:%04x\n", s, a);

					if (asnum) {
						r_cons_printf (cons, "string  \"%s\"\n", asnum);
						free (asnum);
					}
				}
				/* binary and floating point */
				r_str_bits64 (out, n);
				f = d = core->num->fvalue;
				memcpy (&f, &n, sizeof (f));
				memcpy (&d, &n, sizeof (d));
				/* adjust sign for nan floats, different libcs are confused */
				if (isnan (f) && signbit (f)) {
					f = -f;
				}
				if (isnan (d) && signbit (d)) {
					d = -d;
				}
				if (*input ==  'j') {
					pj_ks (pj, "fvalue", r_strf ("%.1lf", core->num->fvalue));
					pj_ks (pj, "float", r_strf ("%ff", f));
					pj_ks (pj, "double", r_strf ("%lf", d));
					pj_ks (pj, "binary", r_strf ("0b%s", out));
					char b36str[16];
					b36_fromnum (b36str, n);
					pj_ks (pj, "base36", b36str);
					r_num_to_ternary (out, n);
					pj_ks (pj, "ternary", r_strf ("0t%s", out));
				} else {
					r_cons_printf (cons, "fvalue  %.1lf\n", core->num->fvalue);
					r_cons_printf (cons, "float   %.15ff\n", f);
					r_cons_printf (cons, "double  %.15lf\n", d);
					r_cons_printf (cons, "binary  0b%s\n", out);
					char b36str[16];
					b36_fromnum (b36str, n);
					r_cons_printf (cons, "base36  %s\n", b36str);
					r_num_to_ternary (out, n);
					r_cons_printf (cons, "ternary 0t%s\n", out);
				}
			}
			if (*input ==  'j') {
				pj_end (pj);
			}
			free (inputs);
			r_list_free (list);
			if (pj) {
				r_cons_printf (cons, "%s\n", pj_string (pj));
				pj_free (pj);
			}
		}
		break;
	case 'q': // "?q"
		if (core->num->dbz) {
			R_LOG_ERROR ("Division by Zero");
		}
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_question, "?q");
		} else {
			const char *space = strchr (input, ' ');
			if (space) {
				n = r_num_math (core->num, space + 1);
			} else {
				n = r_num_math (core->num, "$?");
			}
			r_core_return_value (core, n);
		}
		break;
	case 'v': // "?v"
		{
			const char *space = strchr (input, ' ');
			if (space) {
				n = r_num_math (core->num, space + 1);
			} else if (input[1] == ':') {
				n = r_num_math (core->num, input + 2);
			} else if (input[1] && input[2] == ':') {
				n = r_num_math (core->num, input + 3);
			} else {
				n = r_num_math (core->num, "$?");
			}
			if (core->num->nc.errors > 0) {
				if (core->num->nc.calc_err) {
					R_LOG_ERROR ("%s", core->num->nc.calc_err);
				} else {
					R_LOG_ERROR ("RNum.error");
				}
			}
			if (core->num->dbz) {
				R_LOG_ERROR ("Division by Zero");
			}
		}
		switch (input[1]) {
		case '?':
			r_core_cmd_help_contains (core, help_msg_question, "?v");
			break;
		case '\0':
			r_cons_printf (core->cons, "%d\n", (st32)n);
			break;
		case 'x': // "?vx"
			r_cons_printf (core->cons, "0x%08"PFMT64x"\n", n);
			break;
		case 'i': // "?vi"
			switch (input[2]) {
			case '1': // byte
				r_cons_printf (core->cons, "%d\n", (st8)(n & UT8_MAX));
				break;
			case '2': // word
				r_cons_printf (core->cons, "%d\n", (st16)(n & UT16_MAX));
				break;
			case '4': // dword
				r_cons_printf (core->cons, "%d\n", (st32)(n & UT32_MAX));
				break;
			case '8': // qword
				r_cons_printf (core->cons, "%"PFMT64d"\n", (st64)(n & UT64_MAX));
				break;
			default:
				r_cons_printf (core->cons, "%"PFMT64d"\n", n);
				break;
			}
			break;
		case 'd':
			r_cons_printf (core->cons, "%"PFMT64d"\n", n);
			break;
		default:
			r_cons_printf (core->cons, "0x%"PFMT64x"\n", n);
			break;
		}
		r_core_return_value (core, n); // redundant
		break;
	case '=': // "?=" set num->value
		if (input[1] == '=') { // ?==
			if (input[2] == ' ') {
				char *s = strdup (input + 3);
				char *e = strchr (s, ' ');

				if (e) {
					*e++ = 0;
					e = (char *)r_str_trim_head_ro (e);
					int val = strcmp (s, e);
					r_core_return_value (core, val);
				} else {
					R_LOG_ERROR ("Missing secondary word in expression to compare");
				}
				free (s);
			} else {
				r_core_cmd_help_match (core, help_msg_question, "?==");
			}
		} else {
			if (input[1]) { // ?=
				r_num_math (core->num, input + 1);
			} else {
				r_cons_printf (core->cons, "0x%"PFMT64x"\n", core->num->value);
			}
		}
		break;
	case '+': // "?+"
		if (input[1]) {
			st64 n = (st64)core->num->value;
			if (n > 0) {
				r_core_cmd (core, input + 1, 0);
			}
		} else {
			r_cons_printf (core->cons, "0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '-': // "?-"
		if (input[1]) {
			st64 n = (st64)core->num->value;
			if (n < 0) {
				r_core_cmd (core, input + 1, 0);
			}
		} else {
			r_cons_printf (core->cons, "0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '!': // "?!"
		if (input[1]) {
			if (!core->num->value) {
				if (input[1] == '?') {
					cmd_help_exclamation (core);
					return 0;
				}
				int cmdres = r_core_cmd (core, input + 1, 0);
				r_core_return_value (core, cmdres);
				return cmdres;
			}
		} else {
			r_cons_printf (core->cons, "0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '@': // "?@"
		if (input[1] == '@') {
			if (input[2] == '@') {
				r_core_cmd_help (core, help_msg_at_at_at);
			} else {
				r_core_cmd_help (core, help_msg_at_at);
			}
		} else {
			r_core_cmd_help (core, help_msg_at);
		}
		break;
	case '&': // "?&"
		r_core_cmd_help (core, help_msg_amper);
		break;
	case '%': // "?%"
		if (input[1] == '?') {
			cmd_help_percent (core);
		}
		break;
	case '$': // "?$"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_question_v);
		} else {
			int i = 0;
			const char *vars[] = {
				"$$", "$$c", "$$$", "$$$c", "$?", "$b", "$c", "$Cn", "$D", "$DB", "$DD", "$Dn",
				"$is", "$ij", "$if", "$ir", "$iv", "$in", "$ip",
				"$fb", "$fs", "$fd", "$fe", "$f",
				"$e",
				"$BB", "$BI", "$Bi", "$BS", "$BE", "$BD", "$BC", "$B", "$BJ", "$Bj", "$BF", "$Bf",
				"$FB", "$FI", "$FS", "$FE", "$Fs", "$FD", "$F",
				"$Ja", "$M", "$MM",
				"$o", "$p", "$P", "$s",
				"$S", "$SS", "$SB", "$SD", "$SE",
				"$w", "$Xn", NULL
			};
			const bool wideOffsets = r_config_get_i (core->config, "scr.wideoff");
			while (vars[i]) {
				const char *pad = r_str_pad (' ', 6 - strlen (vars[i]));
				if (wideOffsets) {
					eprintf ("%s %s 0x%016"PFMT64x"\n", vars[i], pad, r_num_math (core->num, vars[i]));
				} else {
					eprintf ("%s %s 0x%08"PFMT64x"\n", vars[i], pad, r_num_math (core->num, vars[i]));
				}
				i++;
			}
		}
		return true;
	case 'g':
		if (input[1] == 'e') { // "?ge"
			const char *cmd = r_str_trim_head_ro (input + 3);
			if (*cmd && (st64)core->num->value > 0) {
				r_core_cmd (core, cmd, 0);
			}
		} else {
			r_core_return_invalid_command (core, "?g", input[1]);
		}
		break;
	case 'n':
		if (input[1] == 'e') { // "?ne"
			const char *cmd = r_str_trim_head_ro (input + 3);
			if (*cmd && core->num->value) {
				r_core_cmd (core, cmd, 0);
			}
		} else {
			r_core_return_invalid_command (core, "?n", input[1]);
		}
		break;
	case 'V': // "?V"
		switch (input[1]) {
		case '?': // "?V?"
			r_core_cmd_help (core, help_msg_question_V);
			break;
		case 0: // "?V"
			{
				char *v = r_str_version ("radare2");
				if (v) {
					r_cons_printf (core->cons, "%s\n", v);
				}
				free (v);
			}
			break;
		case 'c': // "?Vc"
			r_cons_printf (core->cons, "%d\n", vernum (R2_VERSION));
			break;
		case 'j': // "?Vj"
			{
				PJ *pj = r_core_pj_new (core);
				pj_o (pj);
				pj_ks (pj, "arch", R_SYS_ARCH);
				pj_ks (pj, "os", R_SYS_OS);
				pj_ki (pj, "bits", R_SYS_BITS);
				pj_ki (pj, "commit", R2_VERSION_COMMIT);
				pj_ks (pj, "tap", R2_GITTAP);
				pj_ki (pj, "major", R2_VERSION_MAJOR);
				pj_ki (pj, "minor", R2_VERSION_MINOR);
				pj_ki (pj, "patch", R2_VERSION_PATCH);
				pj_ki (pj, "number", R2_VERSION_NUMBER);
				pj_ki (pj, "nversion", vernum (R2_VERSION));
				pj_ks (pj, "version", R2_VERSION);
				pj_end (pj);
				r_cons_printf (core->cons, "%s\n", pj_string (pj));
				pj_free (pj);
			}
			break;
		case 'n': // "?Vn"
			r_cons_printf (core->cons, "%d\n", R2_VERSION_NUMBER);
			break;
		case 'q': // "?Vq"
			r_cons_println (core->cons, R2_VERSION);
			break;
		case '0':
			r_cons_printf (core->cons, "%d\n", R2_VERSION_MAJOR);
			break;
		case '1':
			r_cons_printf (core->cons, "%d\n", R2_VERSION_MINOR);
			break;
		case '2':
			r_cons_printf (core->cons, "%d\n", R2_VERSION_PATCH);
			break;
		default:
			r_core_return_invalid_command (core, "?V", input[1]);
			break;
		}
		break;
	case 'l': // "?l"
		if (input[1] == 'e') { // "?le"
			const char *cmd = r_str_trim_head_ro (input + 3);
			if (*cmd && (st64)core->num->value < 0) {
				r_core_cmd (core, cmd, 0);
			}
		} else if (input[1] == 'q') {
			input = r_str_trim_head_ro (input + 2);
			r_core_return_value (core, strlen (input));
		} else if (input[1] == '?') {
			r_core_cmd_help_contains (core, help_msg_question, "?l");
		} else {
			input = r_str_trim_head_ro (input + 1);
			r_core_return_value (core, strlen (input));
			r_cons_printf (core->cons, "%" PFMT64d "\n", core->num->value);
		}
		break;
	case 'X': // "?X"
		input = r_str_trim_head_ro (input + 1);
		n = r_num_math (core->num, input);
		r_cons_printf (core->cons, "%"PFMT64x"\n", n);
		break;
	case 'x': // "?x"
		input = r_str_trim_head_ro (input + 1);
		if (*input == '-') {
			ut8 *out = malloc (strlen (input) + 1);
			if (out) {
				int len = r_hex_str2bin (input + 1, out);
				if (len >= 0) {
					out[len] = 0;
					r_cons_println (core->cons, (const char*)out);
				} else {
					R_LOG_ERROR ("invalid hexpair string");
				}
				free (out);
			}
		} else if (*input == '+') {
			ut64 n = r_num_math (core->num, input);
			int bits = r_num_to_bits (NULL, n) / 8;
			for (i = 0; i < bits; i++) {
				r_cons_printf (core->cons, "%02x", (ut8)((n >> (i * 8)) &0xff));
			}
			r_cons_newline (core->cons);
		} else {
			input = r_str_trim_head_ro (input);
			for (i = 0; input[i]; i++) {
				r_cons_printf (core->cons, "%02x", input[i]);
			}
			r_cons_newline (core->cons);
		}
		break;
	case 'E': // "?E" clippy echo
		r_core_clippy (core, input + 1);
		break;
	case 'e': // "?e" echo
		if (input[1] == 'q') { // "?eq"
			const char *cmd = r_str_trim_head_ro (input + 3);
			if (*cmd && core->num->value == 0) {
				r_core_cmd (core, cmd, 0);
			} else {
				r_core_return_value (core, core->num->value);
			}
			break;
		}
		if (input[1] == ' ' && (input[2] == '"' || input[2] == '\'')) {
			r_str_trim_args ((char *)input);
		}
		switch (input[1]) {
		case 'a': // "?ea hello world
			{
				char *s = r_str_ss (r_str_trim_head_ro (input + 2), NULL, 0);
				r_cons_println (core->cons, s);
				free (s);
			}
			break;
		case 't': // "?et" "?e=t newtitle"
			r_cons_set_title (core->cons, r_str_trim_head_ro (input + 2));
			break;
		case ':': { // "?e:"
				const char *arg = r_str_trim_head_ro (input + 2);
				int res_len = 0;
				ut8 *res = r_base64_decode_dyn (arg, -1, &res_len);
				if (res && res_len > 0) {
					r_cons_write (core->cons, (const char *)res, res_len);
				}
				free (res);
			}
			break;
		case '=': { // "?e="
				ut64 pc = r_num_math (core->num, input + 2);
				r_print_progressbar (core->print, pc, 80, NULL);
				r_cons_newline (core->cons);
			}
			break;
		case 'b': { // "?eb"
			char *arg = strdup (r_str_trim_head_ro (input + 2));
			int n = r_str_split (arg, ' ');
			ut64 *portions = calloc (n, sizeof (ut64));
			for (i = 0; i < n; i++) {
				portions[i] = r_num_math (core->num, r_str_word_get0 (arg, i));
			}
			r_print_portionbar (core->print, portions, n);
			R_FREE (arg);
			R_FREE (portions);
			break;
		}
		case 's': // "?es"
			  {
				  char *msg = strdup (input + 2);
				  r_str_trim (msg);
				  char *p = strchr (msg, '&');
				  if (p) {
					  *p = 0;
				  }
				  r_sys_tts (msg, p);
				  free (msg);
			  }
			break;
		case 'c': // "?ec" column
			r_cons_column (core->cons, r_num_math (core->num, input + 2));
			break;
		case 'v':
			colormessage (core, input + 2);
			break;
		case 'g': { // "?eg" gotoxy
			int x = atoi (input + 2);
			char *arg = strchr (input + 2, ' ');
			int y = arg? atoi (arg + 1): 0;
			r_cons_gotoxy (core->cons, x, y);
			}
			break;
		case 'n': { // "?en" echo -n
			const char *msg = r_str_trim_head_ro (input + 2);
			// TODO: replace all ${flagname} by its value in hexa
			char *newmsg = filterFlags (core, msg);
			r_str_unescape (newmsg);
			r_cons_print (core->cons, newmsg);
			free (newmsg);
			break;
		}
		case 'f': // "?ef"
			{
				const char *text = r_str_trim_head_ro (input + 2);
				int len = strlen (text) + 2;
				RStrBuf *b = r_strbuf_new ("");
				r_strbuf_append (b, ".");
				r_strbuf_append (b, r_str_pad ('-', len));
				r_strbuf_append (b, ".\n");
				r_strbuf_append (b, "| ");
				r_strbuf_append (b, text);
				r_strbuf_append (b, " |\n");
				r_strbuf_append (b, "'");
				r_strbuf_append (b, r_str_pad ('-', len));
				r_strbuf_append (b, "'\n");
				char * s = r_strbuf_drain (b);
				r_cons_print (core->cons, s);
				free (s);
			}
			break;
		case 'e': // "?ee"
			eprintf ("%s\n", r_str_trim_head_ro (input + 2));
			break;
		case 'i': // "?ei"
			R_LOG_INFO ("%s", r_str_trim_head_ro (input + 2));
			break;
		case 'd': // "?ed"
			  if (input[2] == 'd') {
				  int i,j;
				  r_cons_show_cursor (core->cons, 0);
				  r_cons_clear00 (core->cons);
				  for (i = 1; i < 100; i++) {
					  if (r_cons_is_breaked (core->cons)) {
						  break;
					  }
					  for (j = 0; j < 20; j++) {
						  char *d = r_str_donut (i);
						  r_cons_gotoxy (core->cons, 0, 0);
						  r_str_trim_tail (d);
						  r_cons_clear_line (core->cons, 0);
						  r_cons_printf (core->cons, "Downloading the Gibson...\n\n");
						  r_core_cmdf (core, "?e=%d", i);
						  r_cons_print (core->cons, d);
						  r_cons_clear_line (core->cons, 0);
						  r_cons_newline (core->cons);
						  free (d);
						  r_cons_flush (core->cons);
						  r_sys_usleep (2000);
					  }
				  }
				  r_cons_clear00 (core->cons);
				  r_cons_printf (core->cons, "\nPayload installed. Thanks for your patience.\n\n");
			} else {
				  char *d = r_str_donut (r_num_math (core->num, input + 2));
				  r_str_trim_tail (d);
				  const char *color = (core->cons && core->cons->context->pal.flag)? core->cons->context->pal.flag: "";
				  r_cons_printf (core->cons, "%s%s", color, d);
				  r_cons_newline (core->cons);
				  free (d);
			}
			break;
		case 'm': // "?em"
			  {
				  char *word, *str = strdup (r_str_trim_head_ro (input + 2));
				  char *legend = strchr (str, ',');
				  RList *llist = NULL;
				  if (legend) {
					  *legend = 0;
					  r_str_trim (legend + 1);
					  llist = r_str_split_list (strdup (legend + 1), " ", 0);
				  }
				  r_str_trim (str);
				  RList *list = r_str_split_list (str, " ", 0);
				  int *nums = calloc (sizeof (int), r_list_length (list));
				  char **text = calloc (sizeof (char *), r_list_length (list));
				  int i = 0;
				  r_list_foreach (list, iter, word) {
					st64 n = r_num_math (core->num, word);
					if (n >= ST32_MAX || n < 0) {
						R_LOG_WARN ("Number out of range");
					}
					nums[i] = n;
					i++;
				  }
				  int j = 0;
				  r_list_foreach (llist, iter, word) {
					  if (j >= i) {
						  break;
					  }
					  text[j] = word;
					  j++;
				  }
				  // const int size = r_config_get_i (core->config, "hex.cols");
				  int h, w = r_cons_get_size (core->cons, &h);
				  h /= 2;
				  char *res = r_print_treemap (r_list_length (list), nums, (const char**)text, w, h);
				  r_cons_println (core->cons, res);
				  free (res);
				  free (text);
				  r_list_free (list);
				  r_list_free (llist);
			  }
			break;
		case 'p': // "?ep"
			  {
				  char *word, *str = strdup (r_str_trim_head_ro (input + 2));
				  char *legend = strchr (str, ',');
				  RList *llist = NULL;
				  if (legend) {
					  *legend = 0;
					  r_str_trim (legend + 1);
					  llist = r_str_split_list (strdup (legend + 1), " ", 0);
				  }
				  r_str_trim (str);
				  RList *list = r_str_split_list (str, " ", 0);
				  int *nums = calloc (sizeof (int), r_list_length (list));
				  char **text = calloc (sizeof (char *), r_list_length (list));
				  int i = 0;
				  r_list_foreach (list, iter, word) {
					st64 n = r_num_math (core->num, word);
					if (n >= ST32_MAX || n < 0) {
						R_LOG_WARN ("Number out of range");
					}
					nums[i] = n;
					i++;
				  }
				  int j = 0;
				  r_list_foreach (llist, iter, word) {
					  if (j >= i) {
						  break;
					  }
					  text[j] = word;
					  j++;
				  }
				  const int size = r_config_get_i (core->config, "hex.cols");
				  r_print_pie (core->print, r_list_length (list), nums, (const char**)text, size);
				  free (text);
				  r_list_free (list);
				  r_list_free (llist);
			  }
			break;
		case ' ':
			{
				const char *msg = r_str_trim_head_ro (input + 1);
				// TODO: replace all ${flagname} by its value in hexa
				char *newmsg = filterFlags (core, msg);
				r_str_unescape (newmsg);
				r_cons_println (core->cons, newmsg);
				free (newmsg);
				r_core_return_value (core, 0);
			}
			break;
		case 0: // "?e"
			r_cons_newline (core->cons);
			r_core_return_value (core, 0);
			break;
		case '?': // "?e?"
			r_core_cmd_help (core, help_msg_question_e);
			break;
		default:
			r_core_return_invalid_command (core, "?e", input[1]);
			break;
		}
		break;
	case 's': // "?s" sequence from to step
		{
			input = r_str_trim_head_ro (input + 1);
			char *p = strchr (input, ' ');
			if (p) {
				*p = '\0';
				ut64 from = r_num_math (core->num, input);
				char *p2 = strchr (p + 1, ' ');
				int step = 0;
				if (p2) {
					*p2 = '\0';
					step = r_num_math (core->num, p2 + 1);
				}
				if (step < 1) {
					step = 1;
				}
				ut64 to = r_num_math (core->num, p + 1);
				for (; from <= to; from += step) {
					r_cons_printf (core->cons, "%"PFMT64d" ", from);
				}
				r_cons_newline (core->cons);
			}
		}
		break;
	case 'P': // "?P"
		if (core->io->va) {
			ut64 o, n = (input[0] && input[1])?
				r_num_math (core->num, input + 2): core->addr;
			RIOMap *map = r_io_map_get_paddr (core->io, n);
			if (map) {
				o = n + r_io_map_begin (map) - map->delta;
				r_cons_printf (core->cons, "0x%08"PFMT64x"\n", o);
			} else {
				r_cons_printf (core->cons, "no map at 0x%08"PFMT64x"\n", n);
			}
		} else {
			r_cons_printf (core->cons, "0x%08"PFMT64x"\n", core->addr);
		}
		break;
	case 'p': // "?p"
		if (core->io->va) {
			// physical address
			ut64 o, n = (input[0] && input[1])?
				r_num_math (core->num, input + 2): core->addr;
			RIOMap *map = r_io_map_get_at (core->io, n);
			if (map) {
				o = n - r_io_map_begin (map) + map->delta;
				r_cons_printf (core->cons, "0x%08"PFMT64x"\n", o);
			} else {
				r_cons_printf (core->cons, "no map at 0x%08"PFMT64x"\n", n);
			}
		} else {
			r_cons_printf (core->cons, "0x%08"PFMT64x"\n", core->addr);
		}
		break;
	case '_': // "?_" hud input
		r_core_yank_hud_file (core, input + 1);
		break;
	case 'i': // "?i" input num
		r_cons_set_raw (core->cons, 0);
		if (!r_cons_is_interactive (core->cons)) {
			R_LOG_ERROR ("Not running in interactive mode");
		} else {
			switch (input[1]) {
			case '?': // "?i?"
				r_core_cmd_help (core, help_msg_question_i);
				break;
			case 'f': // "?if"
				r_core_return_value (core, !r_num_conditional (core->num, input + 2));
				eprintf ("%s\n", r_str_bool (!core->num->value));
				break;
			case 'm': // "?im"
				r_cons_message (core->cons, input + 2);
				break;
			case 'p': // "?ip"
				{
					const bool interactive = r_config_get_b (core->config, "scr.interactive");
					if (interactive) {
						r_core_return_value (core, r_core_yank_hud_path (core, input + 2, 0) == true);
					} else {
						R_LOG_WARN ("?ip requires scr.interactive=true");
					}
				}
				break;
			case 'e': // "?ie"
				{
				char foo[1024];
				r_cons_flush (core->cons);
				input = r_str_trim_head_ro (input + 2);
				// TODO: r_cons_input()
				snprintf (foo, sizeof (foo) - 1, "%s: ", input);
				r_line_set_prompt (core->cons->line, foo);
				r_cons_fgets (core->cons, foo, sizeof (foo), 0, NULL);
				foo[sizeof (foo) - 1] = 0;
				r_cons_printf (core->cons, "%s\n", foo);
				r_core_return_value (core, 0);
				}
				break;
			case 'k': // "?ik"
				 r_cons_any_key (core->cons, NULL);
				 break;
			case 'y': // "?iy"
				 input = r_str_trim_head_ro (input + 2);
				 r_core_return_value (core, r_cons_yesno (cons, 1, "%s? (Y/n)", input));
				 break;
			case 'u':
				 r_core_return_value (core, cmd_qiu (core, r_str_trim_head_ro (input + 2)));
				 break;
			case 'n': // "?in"
				input = r_str_trim_head_ro (input + 2);
				 r_core_return_value (core, r_cons_yesno (cons, 0, "%s? (y/N)", input));
				 break;
			default: {
				char foo[1024];
				r_cons_flush (core->cons);
				input = r_str_trim_head_ro (input + 1);
				// TODO: use r_cons_input()
				snprintf (foo, sizeof (foo) - 1, "%s: ", input);
				r_line_set_prompt (core->cons->line, foo);
				r_cons_fgets (core->cons, foo, sizeof (foo), 0, NULL);
				foo[sizeof (foo) - 1] = 0;
				r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, foo, strlen (foo) + 1);
				r_core_return_value (core, r_num_math (core->num, foo));
				}
				break;
			}
		}
		r_cons_set_raw (core->cons, 0);
		break;
	case 'w': // "?w"
		{
			  ut64 addr = r_num_math (core->num, input + 1);
			  char *rstr = core->print->hasrefs (core->print->user, addr, true);
			  if (!rstr) {
				  R_LOG_ERROR ("Cannot get refs at 0x%08"PFMT64x, addr);
				  break;
			  }
			  r_cons_println (core->cons, rstr);
			  free (rstr);
		}
		break;
	case '?': // "??"
		if (input[1] == 0) { // "??"
			r_core_cmd_help (core, help_msg_question);
			return 0;
		} else if (input[1]) {
			if (core->num->value) {
				r_core_cmd (core, input + 1, 0);
				//r_core_return_value (core, rc);
			}
		} else {
			if (core->num->dbz) {
				R_LOG_ERROR ("Division by Zero");
			}
			r_cons_printf (core->cons, "%"PFMT64d"\n", core->num->value);
		}
		break;
	case '\0': // "?"
		// TODO #7967 help refactor
		r_core_cmd_help (core, help_msg_intro);
		r_core_cmd_help (core, help_msg_root);
		break;
	default:
		r_core_return_invalid_command (core, "?", input[0]);
		break;
	}
	return 0;
}

static RCoreHelpMessage help_msg_h = {
	"help", "", "Show a friendly message",
	"head", " [n] [file]", "Print first n lines in file (default n=5)",
	NULL
};

static void cmd_head(void *data, const char *_input) { // "head"
	RCore *core = (RCore *)data;
	int lines = 5;
	char *input = strdup (_input);
	char *arg = strchr (input, ' ');
	char *tmp, *count;
	if (arg) {
		arg = (char *)r_str_trim_head_ro (arg + 1); // contains "count filename"
		count = strchr (arg, ' ');
		if (count) {
			*count = 0;	// split the count and file name
			tmp = (char *)r_str_trim_head_ro (count + 1);
			lines = atoi (arg);
			arg = tmp;
		}
	}
	switch (*input) {
	case '?': // "head?"
		r_core_cmd_help (core, help_msg_h);
		break;
	default: // "head"
		if (!arg) {
			arg = "";
		}
		if (r_fs_check (core->fs, arg)) {
			r_core_cmdf (core, "md %s", arg);
		} else {
			char *res = r_syscmd_head (arg, lines);
			if (res) {
				r_cons_print (core->cons, res);
				free (res);
			}
		}
		break;
	}
	free (input);
}

static int cmd_h(void *data, const char *_input) { // "head"
	RCore *core = (RCore *)data;
	if (r_str_startswith (_input, "ead")) {
		cmd_head (data, _input);
		return 0;
	}
	if (r_str_startswith (_input, "elp")) {
		r_cons_printf (core->cons, "%s\n", help_message);
		return 0;
	}
	r_core_cmd_help ((RCore*)data, help_msg_h);
	return 0; // invalid command
}
#endif
