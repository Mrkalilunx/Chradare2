/**
 * manr2 插件
 * 提供 manr2 命令,输出 radare2 命令的中文手册
 * 采用捕获替换方案:运行时捕获 xxx? 英文帮助,按翻译表逐行替换为中文
 * 命令串与参数取自 r2 实际输出,主题色也取自当前调色板,天然同步
 * 翻译表在 manr2dict.h,与业务逻辑分离
 * r2 变量 manr2.auto 为真时任意 xxx? 帮助请求自动渲染中文,默认开启
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <dlfcn.h>
#include <r_core.h>
#include "manr2dict.h"

#define MANR2_PREFIX "manr2"
#define MANR2_AUTOCFG "manr2.auto" // r2 配置键,为真开启自动接管,默认开启
#define MANR2_GAP 2 // 命令列补齐后到说明的空格数

/**
 * 在翻译表中精确查英文文本
 *
 * @param dict 翻译表,空指针结束
 * @param key 待查英文文本
 * @return 命中返回中文译文,未命中返回空指针
 */
static const char *manr2trans(const Manr2Dict *dict, const char *key)
{
	if (!dict || !key) {
		return NULL;
	}
	size_t i;
	for (i = 0; dict[i].en; i++) {
		if (!strcmp (dict[i].en, key)) {
			return dict[i].zh;
		}
	}
	return NULL;
}

// 动态翻译表,运行时从 tsv 加载,空指针结束
static Manr2Dict *g_usage = NULL; // 动态 usage 表
static Manr2Dict *g_dict = NULL; // 动态 desc/标题表
static Manr2Dict *g_argtab = NULL; // 动态参数占位符表

/**
 * 从 tsv 追加词条到动态表
 * tsv 每行三个字段:类型\ten\tzh,类型 u/d/a 分别对应 usage/desc/arg
 * 两文件先后读入,同一键后者覆盖前者,实现扩展表覆盖官方表
 *
 * @param name 表名(usage/desc/arg),决定追加到哪张表
 * @param en 英文键
 * @param zh 中文值
 */
static void manr2tabadd(const char *name, const char *en, const char *zh)
{
	Manr2Dict **dst = !strcmp (name, "u") ? &g_usage
		: !strcmp (name, "a") ? &g_argtab : &g_dict;
	size_t n = 0;
	while ((*dst) && (*dst)[n].en) {
		n++;
	}
	Manr2Dict *nt = realloc (*dst, (n + 2) * sizeof (Manr2Dict)); // 末尾留空终止行
	if (!nt) {
		return;
	}
	*dst = nt;
	nt[n].en = strdup (en);
	nt[n].zh = strdup (zh);
	nt[n + 1].en = NULL;
	nt[n + 1].zh = NULL;
}

/**
 * 从 tsv 文件加载词条到动态表
 * 按行解析,忽略空行与注释行,字段不足 3 个跳过
 *
 * @param path tsv 文件路径
 * @return 解析到词条返回 true,文件不可读返回 false
 */
static bool manr2tsvload(const char *path)
{
	FILE *f = fopen (path, "r");
	if (!f) {
		return false;
	}
	char ln[4096];
	while (fgets (ln, sizeof (ln), f)) {
		if (ln[0] == '\n' || ln[0] == '#') {
			continue;
		}
		char *p = ln;
		while (*p && !isspace ((unsigned char) *p)) {
			p++;
		}
		if (!*p) {
			continue;
		}
		*p = 0;
		char *en = p + 1;
		p = en;
		while (*p && *p != '\t') {
			p++;
		}
		if (!*p) {
			continue;
		}
		*p = 0;
		char *zh = p + 1;
		size_t zl = strlen (zh);
		while (zl && (zh[zl - 1] == '\n' || zh[zl - 1] == '\r')) {
			zh[--zl] = 0;
		}
		manr2tabadd (ln, en, zh);
	}
	fclose (f);
	return true;
}

/**
 * 定位当前插件 .so 的目录
 * 用 dladdr 取本函数地址所在模块路径,截取目录部分
 *
 * @param out 输出缓冲
 * @param sz 缓冲大小
 */
static void manr2sodir(char *out, size_t sz)
{
	Dl_info di;
	if (dladdr ((void *) manr2sodir, &di) && di.dli_fname && di.dli_fname[0]) {
		snprintf (out, sz, "%s", di.dli_fname);
		char *sl = strrchr (out, '/');
		if (sl) {
			*sl = 0;
		}
	} else {
		snprintf (out, sz, ".");
	}
}

/**
 * 加载全部翻译表
 * 优先读插件同目录 manr2.tsv 与 manr2ext.tsv
 * 任一 tsv 缺失时保留内置空表,不阻断插件功能
 */
static void manr2tabload(void)
{
	if (g_usage || g_dict || g_argtab) { // 已加载过,防重复
		return;
	}
	char dir[512];
	manr2sodir (dir, sizeof (dir));
	char p1[640];
	char p2[640];
	snprintf (p1, sizeof (p1), "%s/manr2.tsv", dir);
	snprintf (p2, sizeof (p2), "%s/manr2ext.tsv", dir);
	manr2tsvload (p1);
	manr2tsvload (p2);
}

/**
 * 释放动态翻译表
 * 先释放每条词条字符串再释放表本体,并置空防止重复释放
 *
 * @param ctx 插件会话上下文,仅作签名对齐,未使用
 * @return 恒返回 true
 */
static bool manr2tabfree(RCorePluginSession *ctx)
{
	Manr2Dict *tabs[] = { g_usage, g_dict, g_argtab };
	size_t t;
	for (t = 0; t < 3; t++) {
		Manr2Dict *d = tabs[t];
		size_t i;
		for (i = 0; d && d[i].en; i++) {
			free ((void *) d[i].en);
			free ((void *) d[i].zh);
		}
		free (d);
	}
	g_usage = NULL;
	g_dict = NULL;
	g_argtab = NULL;
	return true;
}

/**
 * 去除字符串中的 ANSI 转义序列,就地压缩
 *
 * @param s 目标字符串
 */
static void manr2stripesc(char *s)
{
	char *d = s;
	while (*s) {
		if (s[0] == '\x1b' && s[1] == '[') {
			char *e = s + 2;
			while (*e && !((*e >= 'a' && *e <= 'z') || (*e >= 'A' && *e <= 'Z'))) {
				e++;
			}
			s = e + (*e ? 1 : 0);
		} else {
			*d++ = *s++;
		}
	}
	*d = 0;
}

/**
 * 计算 UTF-8 字符串的显示列宽
 * 多字节字符按 2 列计并跳过后续字节,ASCII 按 1 列计
 *
 * @param s 待计算列宽的 UTF-8 字符串
 * @return 字符串的显示列宽
 */
static size_t manr2displen(const char *s)
{
	size_t w = 0; // 累计显示列宽
	while (*s) { // 逐字节遍历
		unsigned char c = (unsigned char) *s; // 当前字节的无符号值
		if (c < 0x80) { // ASCII 单字节 1 列
			w++;
			s++;
			continue;
		}
		w += 2; // 多字节字符按 2 列计
		size_t skip = 0; // 需跳过的后续字节数
		if (c >= 0xC0 && c <= 0xDF) { // 两字节字符
			skip = 1;
		} else if (c >= 0xE0 && c <= 0xEF) { // 三字节字符
			skip = 2;
		} else if (c >= 0xF0 && c <= 0xF7) { // 四字节字符
			skip = 3;
		}
		s++; // 跳过首字节
		while (skip-- > 0 && *s) { // 跳过后续字节,防越过结尾
			s++;
		}
	}
	return w;
}

/**
 * 用指定颜色打印一段文本,颜色关闭时等价于原样输出
 * 颜色仅用于外观,不能代入列宽计算
 *
 * @param cons 输出控制台
 * @param col 颜色转义串,空串表示无色
 * @param s 文本
 * @param n 打印字节数
 */
static void manr2coln(RCons *cons, const char *col, const char *s, size_t n)
{
	if (!n) {
		return;
	}
	if (col && col[0]) {
		r_cons_printf (cons, "%s", col);
	}
	r_cons_printf (cons, "%.*s", (int) n, s);
	if (col && col[0]) {
		r_cons_printf (cons, "%s", Color_RESET);
	}
}

/**
 * 用指定颜色打印一段文本,长度按原文本计算
 *
 * @param cons 输出控制台
 * @param col 颜色转义串,空串表示无色
 * @param s 文本
 */
static void manr2colout(RCons *cons, const char *col, const char *s)
{
	manr2coln (cons, col, s, strlen (s));
}

/**
 * 依次返回当前主题的命令名、参数、说明三色
 * 颜色关闭时返回空串,任一参数可为空指针表示不取
 *
 * @param cons 输出控制台
 * @param colcmd 命令名颜色
 * @param colarg 参数颜色
 * @param colmsg 说明颜色
 */
static void manr2cols(RCons *cons, const char **colcmd, const char **colarg, const char **colmsg)
{
	const char *cc = "";
	const char *ca = "";
	const char *cm = "";
	RConsContext *ctx = cons ? cons->context : NULL;
	if (ctx && ctx->color_mode != COLOR_MODE_DISABLED) {
		if (ctx->pal.input) {
			cc = ctx->pal.input;
		}
		if (ctx->pal.args) {
			ca = ctx->pal.args;
		}
		if (ctx->pal.help) {
			cm = ctx->pal.help;
		}
	}
	if (colcmd) {
		*colcmd = cc;
	}
	if (colarg) {
		*colarg = ca;
	}
	if (colmsg) {
		*colmsg = cm;
	}
}

/**
 * 打印一行带 | 前缀的命令行
 * 命令名着 input 色,参数着 args 色,说明着 help 色
 * 颜色码不入列宽,空缺以空格补齐
 *
 * @param cons 输出控制台
 * @param colcmd 命令名颜色
 * @param colarg 参数颜色
 * @param colmsg 说明颜色
 * @param cmd 命令串,含参数
 * @param zh 说明文本
 * @param fmtw 本页命令段最大显示列宽,说明墙统一对齐到该墙格
 */
static void manr2cmdrow(RCons *cons, const char *colcmd, const char *colarg,
	const char *colmsg, const char *cmd, const char *zh, size_t fmtw)
{
	size_t cl = 0;
	// 首个 [ 或空格或制表符之前算命令名,其后算参数
	while (cmd[cl] && cmd[cl] != '[' && cmd[cl] != ' ' && cmd[cl] != '\t') {
		cl++;
	}
	size_t cw = manr2displen (cmd); // 命令段显示列宽,中文按 2 列计
	size_t cb = strlen (cmd); // 命令段字节数,打印用
	r_cons_printf (cons, "| ");
	manr2coln (cons, colcmd, cmd, cl);
	manr2coln (cons, colarg, cmd + cl, cb - cl);
	size_t pad = cw < fmtw ? fmtw - cw : 0;
	size_t k;
	for (k = 0; k < pad + MANR2_GAP; k++) {
		r_cons_printf (cons, " ");
	}
	manr2colout (cons, colmsg, zh);
	r_cons_printf (cons, "\n");
}

static bool manr2auto_busy = false; // 自动捕获占用标志,防递归

/**
 * 判断自动接管模式的帮助请求
 * r2 变量 manr2.auto 为真且命令为单个命令名加 ? 后缀时视为帮助请求
 * busy 占用期间返回 false,让内嵌捕获放行给 r2 原生执行,避免递归
 *
 * @param core 核心上下文,取 manr2.auto 配置值
 * @param p 命令文本,已剥前后空白
 * @return 命中帮助请求返回 true,否则返回 false
 */
static bool manr2auto(RCore *core, const char *p)
{
	if (manr2auto_busy) {
		return false;
	}
	if (!core || !r_config_get_b (core->config, MANR2_AUTOCFG)) {
		return false;
	}
	size_t n = strlen (p);
	// 纯问号串(?, ??, ???)视为魔法帮助命令,全字符为 ? 即接管
	size_t i;
	for (i = 0; i < n; i++) {
		if (p[i] != '?') {
			break;
		}
	}
	if (i == n) {
		return n > 0;
	}
	// ? 的二级帮助页如 ?e?、?$?、?@?、?>?、?|?、?~?、?&?、?#? 是合法帮助,放行
	// 形态为 ? 开头 ? 结尾,中间段不含空白与命令分隔符
	if (p[0] == '?' && n > 2 && p[n - 1] == '?' && !strpbrk (p + 1, " \t;!:")) {
		return true;
	}
	// 普通帮助请求必须恰好一个 ? 且只在末尾,如 wx? 或 l?
	if (strchr (p, '?') != p + n - 1) {
		return false;
	}
	// 含空白即复合命令,不接管
	if (strpbrk (p, " \t")) {
		return false;
	}
	// 单个特殊字符命令本身(如 !?、&?、|?、;?)是合法帮助,放行
	if (n == 2 && (p[0] == '!' || p[0] == '&' || p[0] == '|' || p[0] == ';' || p[0] == ':')) {
		return true;
	}
	// 命令名中含分隔符或修饰符的复合命令不接管
	if (strpbrk (p, " ;|&!:")) {
		return false;
	}
	return true;
}

/**
 * 判断捕获文本是否像帮助文本
 * 含 Usage: 前缀或 | 前缀行才算有效,否则视为无效命令
 *
 * @param text 捕获文本
 * @return 有效返回 true
 */
static bool manr2valid(const char *text)
{
	if (!text || !text[0]) {
		return false;
	}
	return strstr (text, "Usage:") || strstr (text, "\n| ")
		|| (text[0] == '|' && text[1] == ' ');
}

/**
 * 将源串中的英文参数占位符替换为中文占位符
 * 遇完整方括号对在 manr2argtab 精确查表,命中输出中文,未命中原样保留
 * 枚举型方括号如 [?dfx] 不在此表,天然不被替换
 *
 * @param dst 输出缓冲
 * @param dstsz 输出缓冲容量
 * @param src 源串
 */
static void manr2argtr(char *dst, size_t dstsz, const char *src)
{
	size_t di = 0; // 输出写入位置
	const char *s = src; // 源串游标
	while (*s && di + 1 < dstsz) { // 逐字符拷贝,留出结尾 NUL
		if (*s == '[') { // 占位符起始
			const char *e = strchr (s, ']'); // 行内匹配的结束括号
			if (e) {
				size_t plen = (size_t) (e - s) + 1; // 含两端括号的占位符长度
				const char *zh = NULL; // 查表命中的中文译名
				size_t i; // 词条下标
for (i = 0; g_argtab && g_argtab[i].en; i++) { // 遇 NULL 终止行停止
				if (strlen (g_argtab[i].en) == plen && !strncmp (g_argtab[i].en, s, plen)) { // 整占位符精确匹配
					zh = g_argtab[i].zh;
						break;
					}
				}
				if (zh) {
					size_t zl = strlen (zh);
					if (di + zl >= dstsz) { // 容量不足截断
						break;
					}
					memcpy (dst + di, zh, zl);
					di += zl;
					s = e + 1;
					continue;
				}
			}
		}
		dst[di++] = *s++; // 未命中或非占位符原样复制
	}
	dst[di] = '\0';
}

/**
 * 在命令行文本中找命令串与说明的分界
 * 取首个两空格及以上且后随非空格字符的位置,避免命令串自带短段的干扰
 *
 * @param s 行文本,从 | 之后起
 * @return 分界指针,未找到返回空指针
 */
static const char *manr2split(const char *s)
{
	const char *p = s;
	while (*p) {
		if (*p == ' ' || *p == '\t') {
			const char *q = p;
			while (*q == ' ' || *q == '\t') {
				q++;
			}
			if (q - p >= 2 && *q) {
				return q;
			}
			p = q;
		} else {
			p++;
		}
	}
	return NULL;
}

/**
 * 解析捕获的帮助文本并逐行渲染
 * 用法行、命令行、标题行分别处理,说明与标题走翻译表
 *
 * @param cons 输出控制台
 * @param text 捕获文本,可为空
 * @return 是否有可用的帮助行
 */
static bool manr2render(RCons *cons, const char *text)
{
	const char *colcmd = "";
	const char *colarg = "";
	const char *colmsg = "";
	manr2cols (cons, &colcmd, &colarg, &colmsg);
	if (!manr2valid (text)) {
		return false;
	}
	size_t fmtw = 0; // 本页 | 行命令段显示宽上限,预扫求得
	const char *scan = text;
	while (scan && *scan) { // 预扫算对齐列,同 r2 的 r_cons_cmd_help
		const char *snl = strchr (scan, '\n');
		size_t slen = snl ? (size_t) (snl - scan) : strlen (scan);
		if (slen) {
			char *s = strndup (scan, slen);
			manr2stripesc (s);
			if (s[0] == '|' && s[1] == ' ') { // 仅 | 命令行参与列宽
				const char *sc = manr2split (s + 2);
				if (sc && sc[0]) {
					size_t cl2 = (size_t) (sc - (s + 2));
					while (cl2 && (s[2 + cl2 - 1] == ' ' || s[2 + cl2 - 1] == '\t')) {
						cl2--;
					}
					if (cl2) {
						char scmd[128];
						if (cl2 > sizeof (scmd) - 1) {
							cl2 = sizeof (scmd) - 1;
						}
						memcpy (scmd, s + 2, cl2);
						scmd[cl2] = 0;
						char sm[256]; // 预扫的翻译命令段缓冲
						manr2argtr (sm, sizeof (sm), scmd);
						size_t sw = manr2displen (sm); // 翻译后命令段显示宽
						if (sw > fmtw) {
							fmtw = sw;
						}
					}
				}
			}
			free (s);
		}
		if (!snl) {
			break;
		}
		scan = snl + 1;
	}
	bool used = false;
	const char *line = text;
	while (line && *line) {
		const char *nl = strchr (line, '\n');
		size_t len = nl ? (size_t) (nl - line) : strlen (line);
		if (len) {
			char *buf = strndup (line, len);
			manr2stripesc (buf);
			if (!buf[0]) {
				// 纯颜色行等价空行
				r_cons_printf (cons, "\n");
			} else if (!strncmp (buf, "Usage:", 6)) {
				const char *rest = buf + 6;
				const char *zh = manr2trans (g_usage, rest);
				char mrest[256]; // 参数占位符翻译缓冲
				manr2argtr (mrest, sizeof (mrest), zh ? zh : rest);
				r_cons_printf (cons, "用法:");
				manr2colout (cons, colarg, mrest);
				r_cons_printf (cons, "\n");
				used = true;
			} else if (buf[0] == '|' && buf[1] == ' ') {
				const char *desc = manr2split (buf + 2);
				if (desc && desc[0]) {
					size_t cl = (size_t) (desc - (buf + 2));
					while (cl && (buf[2 + cl - 1] == ' ' || buf[2 + cl - 1] == '\t')) {
						cl--;
					}
					const char *zh = manr2trans (g_dict, desc);
					if (cl) {
						char cmd[128];
						if (cl > sizeof (cmd) - 1) {
							cl = sizeof (cmd) - 1;
						}
						memcpy (cmd, buf + 2, cl);
						cmd[cl] = 0;
						char mc[256]; // 命令段参数占位符翻译缓冲
						manr2argtr (mc, sizeof (mc), cmd);
						manr2cmdrow (cons, colcmd, colarg, colmsg,
							mc, zh ? zh : desc, fmtw);
					} else {
						// 无命令段全空则按待翻说明输出
						char mc[256]; // 命令段参数占位符翻译缓冲
						char mdc[256]; // 说明参数占位符翻译缓冲
						manr2argtr (mc, sizeof (mc), desc);
						manr2argtr (mdc, sizeof (mdc), zh ? zh : desc);
						manr2cmdrow (cons, colcmd, colarg, colmsg,
							mc, mdc, fmtw);
					}
				} else {
					r_cons_printf (cons, "%s\n", buf);
				}
				used = true;
			} else {
				const char *zh = manr2trans (g_dict, buf);
				manr2colout (cons, colmsg, zh ? zh : buf);
				r_cons_printf (cons, "\n");
				used = true;
			}
			free (buf);
		} else {
			r_cons_printf (cons, "\n");
		}
		if (!nl) {
			break;
		}
		line = nl + 1;
	}
	return used;
}

/**
 * 打印 manr2 帮助文本
 *
 * @param cons 输出控制台
 */
static void manr2help(RCons *cons)
{
	// r2 帮助排版:首行 Usage: 说明,后续行 | 前缀,命令列对齐到 10 列再补 2 空格
	r_cons_printf (cons, "Usage: manr2 [cmd]   # 按命令名查中文手册,命令串与参数取自 r2 自身\n");
	r_cons_printf (cons, "| manr2 help    显示本帮助,any \"xxx?\" 输出自动接管\n");
	r_cons_printf (cons, "| manr2 ag      查图命令手册\n");
	r_cons_printf (cons, "| manr2 agn     查节点命令手册\n");
	r_cons_printf (cons, "| manr2.auto    开关自动接管(0/1)\n");
}

/**
 * manr2 命令入口
 * r2 会把整条命令文本传给本回调,需自行比对命令名前缀
 * 命中后捕获对应命令帮助并渲染中文
 * MANR2_AUTO 开启时,任意命令的帮助请求 xxx? 也走同套渲染
 *
 * @param ctx 插件会话,含核心上下文
 * @param input 整条命令文本,含命令名
 * @return 匹配并处理后返回 true,否则返回 false 放行给 r2
 */
static bool manr2call(RCorePluginSession *ctx, const char *input)
{
	if (!ctx || !input) {
		return false;
	}
	const char *p = input;
	while (*p == ' ' || *p == '\t') {
		p++;
	}
	if (strncmp (p, MANR2_PREFIX, sizeof (MANR2_PREFIX) - 1)) {
		if (manr2auto (ctx->core, p)) {
			manr2auto_busy = true;
			RCons *cons = ctx->core->cons;
			char *text = r_core_cmd_str (ctx->core, p);
			manr2auto_busy = false;
			if (!text) {
				r_cons_printf (cons, "manr2: 无法获取 %s 的帮助\n", p);
				return true;
			}
			bool ok = manr2render (cons, text);
			free (text);
			return ok;
		}
		return false;
	}
	// 前缀后必须紧跟空格或结束,否则是其他命令
	char c = p[sizeof (MANR2_PREFIX) - 1];
	if (c && c != ' ' && c != '\t') {
		return false;
	}
	RCons *cons = ctx->core->cons;
	p += sizeof (MANR2_PREFIX) - 1;
	while (*p == ' ' || *p == '\t') {
		p++;
	}
	if (!*p || *p == '?' || !strcmp (p, "help") || !strcmp (p, "-h") || !strcmp (p, "--help")) {
		manr2help (cons);
		return true;
	}
	if (strchr (p, ' ') || strchr (p, '\t') || strchr (p, '?') || strchr (p, '!') || strchr (p, ':') || strchr (p, ';')) {
		r_cons_printf (cons, "manr2: 参数只接受单个命令名,如 ag 或 agD\n");
		return true;
	}
	char cmd[64];
	size_t cmdlen = 0;
	while (*p && cmdlen < sizeof (cmd) - 1) {
		cmd[cmdlen++] = *p++;
	}
	cmd[cmdlen] = 0;
	char cap[96];
	snprintf (cap, sizeof (cap), "%s?", cmd);
	char *text = r_core_cmd_str (ctx->core, cap);
	if (!text) {
		r_cons_printf (cons, "manr2: 无法获取命令 %s 的帮助\n", cmd);
		return true;
	}
	bool ok = manr2render (cons, text);
	free (text);
	if (!ok) {
		r_cons_printf (cons, "manr2: 无此命令 %s,help 查看用法\n", cmd);
	}
	return true;
}

/**
 * 插件初始化回调
 * 用 r_config_node_new 建立 manr2.auto 配置节点,手动接入 config 的
 * 哈希表与节点链表,使 e 命令可读写该键并出现在 e? 列表
 * 默认值为 true,即自动接管开启,运行期可随时用 e manr2.auto 切换
 *
 * @param ctx 插件会话上下文
 * @return 恒返回 true,不阻断插件加载
 */
static bool manr2init(RCorePluginSession *ctx)
{
	if (!ctx || !ctx->core || !ctx->core->config) {
		return true;
	}
	manr2tabload (); // 读插件同目录 tsv,失败保留空表不阻断
	RConfig *cfg = ctx->core->config;
	RConfigNode *node = r_config_node_new (MANR2_AUTOCFG, "true"); // 键含点号,r_config_set_b 不会自动入表
	if (node) {
		ht_pp_insert (cfg->ht, node->name, node); // 键查入哈希表
		r_list_append (cfg->nodes, node); // 节点挂上链表
		r_config_desc (cfg, MANR2_AUTOCFG, "Enable auto-translate of xxx? help output"); // 帮助里的描述
	}
	return true;
}

// 插件元数据,名字与回调共同决定命令识别
static RCorePlugin r_core_plugin_manr2 = {
	.meta = {
		.name = MANR2_PREFIX,
		.desc = "radare2 中文手册,捕获替换",
		.license = "MIT",
		.version = R2_VERSION,
	},
	.init = manr2init,
	.call = manr2call,
	.fini = manr2tabfree, // 插件卸载时释放动态翻译表
};

#ifndef R2_PLUGIN_INCORE
// 动态加载出口,类型为 core 插件
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_manr2,
	.version = R2_VERSION,
};
#endif