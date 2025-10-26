/* radare2 - LGPL - Copyright 2009-2025 - pancake */

#if R_INCLUDE_BEGIN

// R2R db/cmd/cmd_meta

char *getcommapath(RCore *core);

typedef struct {
	RCore *core;
	ut64 filter_offset;
	int filter_format;
	size_t filter_count;
	PJ *pj;
	Sdb *fscache;
} FilterStruct;

static RCoreHelpMessage help_msg_C = {
	"用法:", "C[-LCvsdfm*?][*?] [...]", " # 元数据管理",
	"C", "", "以人类友好的形式列出元信息",
	"C*", "", "以 r2 命令形式列出元信息",
	"C*.", "", "以 r2 命令形式列出当前偏移的元信息",
	"C-", " [len] [[@]addr]", "删除给定地址范围内的元数据",
	"C.", "", "以人类友好的形式列出当前偏移的元信息",
	"CC!", " [@addr]", "使用 $EDITOR 编辑注释",
	"CC", "[?] [-] [comment-text] [@addr]", "添加/删除注释",
	"CC.", "[addr]", "显示当前地址的注释",
	"CCa", "[+-] [addr] [text]", "在给定地址添加/删除注释",
	"CCu", " [comment-text] [@addr]", "添加唯一注释",
	"CF", "[sz] [fcn-sign..] [@addr]", "函数签名",
	"CL", "[-][*] [file:line] [addr]", "显示或添加 '代码行' 信息 (bininfo)",
	"CS", "[-][space]", "管理元空间以过滤注释等..",
	"C[Cthsdmf]", "", "以人类友好的形式列出注释/类型/隐藏/字符串/数据/魔法",
	"C[Cthsdmf]*", "", "以 r2 命令形式列出注释/类型/隐藏/字符串/数据/魔法",
	"Cd", "[-] [size] [repeat] [@addr]", "十六进制转储数据数组 (Cd 4 10 == dword [10])",
	"Cd.", " [@addr]", "显示当前地址的数据大小",
	"Cf", "[?][-] [sz] [0|cnt][fmt] [a0 a1...] [@addr]", "格式化内存 (见 pf?)",
	"Cb", "[?][-] [addr] [@addr]", "绑定两个地址以供引用行使用",
	"Cr", "[?][-] [sz] [r2cmd] [@addr]", "运行给定命令以替换反汇编中的 SZ 字节",
	"Ch", "[-] [size] [@addr]", "隐藏数据",
	"Cm", "[-] [sz] [fmt..] [@addr]", "魔法解析 (见 pm?)",
	"Cs", "[?] [-] [size] [@addr]", "添加字符串",
	"Ct", "[?] [-] [comment-text] [@addr]", "添加/删除类型分析注释",
	"Ct.", "[@addr]", "显示当前或指定地址的注释",
	"Cv", "[?][bsr]", "添加注释到参数",
	"Cz", "[@addr]", "添加字符串 (见 Cs?)",
	NULL
};

static RCoreHelpMessage help_msg_CC = {
	"用法:", "CC[-+!*au] [base64:..|str] @ addr", "",
	"CC!", "", "使用 cfg.editor 编辑注释 (vim, ..)",
	"CC", " [text]", "在当前地址追加注释",
	"CC", "", "以人类友好的形式列出所有注释",
	"CC*", "", "以 r2 命令形式列出所有注释",
	"CC+", " [text]", "在当前地址追加注释",
	"CC,", " [table-query]", "以表格格式列出注释",
	"CCF", " [file]", "显示或设置注释文件",
	"CC-", " @ cmt_addr", "删除给定地址的注释",
	"CC.", "", "显示当前偏移的注释",
	"CCf", "", "列出函数中的注释",
	"CCf-", "", "删除当前函数中的所有注释",
	"CCu", " base64:AA== @ addr", "以 base64 添加注释",
	"CCu", " good boy @ addr", "在给定地址添加好孩子注释",
	NULL
};

// 在我看来，'代码行' 应该是一个通用概念，而不是 dbginfo/dwarf/...
static RCoreHelpMessage help_msg_CL = {
	"用法: CL", ".j-", "@addr - 管理代码行引用 (通过 bin.dbginfo 加载并在 asm.dwarf 中显示)",
	"CL", "", "列出所有代码行信息 (虚拟地址 <-> 源文件:行)",
	"CLf", " [addr]", "显示当前或给定偏移的文件名",
	"CLj", "", "与上述相同，但以 JSON 格式显示 (查看 dir.source 更改查找引用行的路径)",
	"CL*", "", "与上述相同，但以 r2 命令格式显示",
	"CL.", "", "显示所有代码行信息 (虚拟地址 <-> 源文件:行)",
	"CL-", "*", "删除所有缓存的代码行信息",
	"CLL", "[f]", "显示与当前偏移相关的源代码行",
	"CLLf", "", "显示当前函数覆盖的源行 (见 CLL@@i 或 list)",
	"CL+", "file:line @ addr", "注册新的文件:行源细节，r2 将读取该行",
	"CL", " addr file:line", "注册新的文件:行源细节，r2 将读取该行",
	"CL", " addr base64:text", "使用 base64 注册给定地址的新源细节",
	NULL
};

static RCoreHelpMessage help_msg_Ct = {
	"用法: Ct", "[.|-] [@ addr]", " # 管理变量类型的注释",
	"Ct", "", "列出所有变量类型注释",
	"Ct", " comment-text [@ addr]", "在当前或指定地址放置注释",
	"Ct.", " [@ addr]", "显示当前或指定地址的注释",
	"Ct-", " [@ addr]", "删除当前或指定地址的注释",
	NULL
};

static RCoreHelpMessage help_msg_CS = {
	"用法: CS", "[*] [+-][metaspace|addr]", " # 管理元空间",
	"CS", "", "显示元空间",
	"CS", " *", "选择所有元空间",
	"CS", " metaspace", "选择元空间或创建如果它不存在",
	"CS", "-metaspace", "删除元空间",
	"CS", "-*", "删除所有元空间",
	"CS", "+foo", "推送先前的元空间并设置",
	"CS", "-", "弹出到先前的元空间",
	//	"CSm", " [addr]", "将给定地址的元移动到当前元空间",
	"CSr", " newname", "重命名选定的元空间",
	NULL
};

static RCoreHelpMessage help_msg_Cs = {
	"用法:", "Cs[ga-*.] ([size]) [@addr]", "",
	"Cs", " [size] @addr", "添加字符串 (猜测 latin1/utf16le)",
	"Cs", "", "以人类友好的形式列出所有字符串",
	"Cs*", "", "以 r2 命令形式列出所有字符串",
	"Cs-", " [@addr]", "删除字符串",
	"Cs.", "", "显示当前地址的字符串",
	"Cs..", "", "显示当前地址的字符串 + 关于它的信息",
	"Cs.j", "", "以 JSON 格式显示当前地址的字符串",
	"Cs8", " [size] ([@addr])", "添加 utf8 字符串",
	"Csa", " [size] ([@addr])", "添加 ascii/latin1 字符串",
	"Csg", " [size] ([@addr])", "如上，但不需要地址",
	"Csw", " [size] ([@addr])", "添加宽字符串 (utf16)",
	"Csz", " [size] ([@addr])", "定义以零结尾的字符串 (最大长度为 size)",
	"Css", " ([range]) ([@addr])", "定义在给定范围或部分中找到的所有字符串",
	"Cz", " [size] [@addr]", "Csz 的别名",
	NULL
};

static RCoreHelpMessage help_msg_Cvb = {
	"用法:", "Cvb", "[name] [comment]",
	"Cvb?", "", "显示此帮助",
	"Cvb", "", "以人类友好的格式列出所有基指针参数/变量注释",
	"Cvb*", "", "以 r2 格式列出所有基指针参数/变量注释",
	"Cvb-", "[name]", "删除当前偏移的基指针变量/参数的注释",
	"Cvb", " [name]", "显示当前偏移的基指针变量/参数的注释",
	"Cvb", " [name] [comment]", "为当前名称的变量添加/追加注释",
	"Cvb!", "[name]", "使用 cfg 编辑器编辑注释",
	NULL
};

static RCoreHelpMessage help_msg_Cvr = {
	"用法:", "Cvr", "[name] [comment]",
	"Cvr?", "", "显示此帮助",
	"Cvr", "", "以人类友好的格式列出所有基于寄存器的参数注释",
	"Cvr*", "", "以 r2 格式列出所有基于寄存器的参数注释",
	"Cvr-", "[name]", "删除该名称的基于寄存器的参数的注释",
	"Cvr", "[name]", "显示该名称的基于寄存器的参数的注释",
	"Cvr", "[name] [comment]", "为变量添加/追加注释",
	"Cvr!", "[name]", "使用 cfg 编辑器编辑注释",
	NULL
};

static RCoreHelpMessage help_msg_Cvs = {
	"用法:", "Cvs", "[name] [comment]",
	"Cvs!", "[name]", "使用 cfg 编辑器编辑注释",
	"Cvs", "", "以人类友好的格式列出所有基于堆栈的参数/变量注释",
	"Cvs", "[name] [comment]", "为变量添加/追加注释",
	"Cvs", "[name]", "显示具有该名称的堆栈指针变量/参数的注释",
	"Cvs*", "", "以 r2 格式列出所有基于堆栈的参数/变量注释",
	"Cvs-", "[name]", "删除具有该名称的堆栈指针变量/参数的注释",
	"Cvs?", "", "显示此帮助",
	NULL
};

static bool print_meta_offset(RCore *core, ut64 addr, PJ *pj) {
	RBinAddrline *al = r_bin_addrline_get (core->bin, addr);
	if (!al) {
		return false;
	}
	if (pj) {
		pj_o (pj);
		pj_ks (pj, "file", al->file);
		pj_kn (pj, "line", al->line);
		pj_kn (pj, "colu", al->column);
		pj_kn (pj, "addr", addr);
		if (r_file_exists (al->file)) {
			char *row = r_file_slurp_line (al->file, al->line, 0);
			pj_ks (pj, "text", row);
			free (row);
		} else {
			// R_LOG_ERROR ("Cannot open '%s'", file);
		}
		pj_end (pj);
		return true;
	}
	int line = al->line;

	r_cons_printf (core->cons, "file: %s\nline: %d\ncolu: %d\naddr: 0x%08"PFMT64x"\n", al->file, line, al->column, addr);
	int line_old = line;
	if (line >= 2) {
		line -= 2;
	}
	if (r_file_exists (al->file)) {
		int i;
		for (i = 0; i < 5; i++) {
			char *row = r_file_slurp_line (al->file, line + i, 0);
			if (row) {
				r_cons_printf (core->cons, "%c %.3x  %s\n", al->line + i == line_old ? '>' : ' ', line + i, row);
				free (row);
			}
		}
	} else {
		R_LOG_ERROR ("Cannot open '%s'", al->file);
	}
	return true;
}

static bool print_addrinfo_json(void *user, const char *k, const char *v) {
	FilterStruct *fs = (FilterStruct *)user;
	ut64 offset = sdb_atoi (k);
	if (!offset || offset == UT64_MAX) {
		return true;
	}
	char *subst = strdup (v);
	char *colonpos = strchr (subst, '|'); // XXX keep only : for simplicity?
	if (!colonpos) {
		colonpos = strchr (subst, ':');
	}
	if (!colonpos) {
		r_cons_printf (fs->core->cons, "%s\n", subst);
	}
	if (colonpos && (fs->filter_offset == UT64_MAX || fs->filter_offset == offset)) {
		if (fs->filter_format) {
			*colonpos = ':';
	//		r_cons_printf (core->cons, "CL %s %s\n", k, subst);
		} else {
			*colonpos = 0;
	//		r_cons_printf (core->cons, "file: %s\nline: %s\naddr: 0x%08"PFMT64x"\n", subst, colonpos + 1, offset);
		}
		fs->filter_count++;
	}
	const char *file = subst;
	int line = atoi (colonpos + 1);
	ut64 addr = offset;
	PJ *pj = fs->pj;
	if (pj) {
		pj_o (pj);
		pj_ks (pj, "file", file);
		pj_kn (pj, "line", line);
		pj_kn (pj, "addr", addr);
		const char *cached_existance = sdb_const_get (fs->fscache, file, NULL);
		bool file_exists = false;
		if (cached_existance) {
			file_exists = !strcmp (cached_existance, "1");
		} else {
			if (r_file_exists (file)) {
				sdb_set (fs->fscache, file, "1", 0);
			} else {
				sdb_set (fs->fscache, file, "0", 0);
			}
		}
		if (file_exists) {
			char *row = r_file_slurp_line (file, line, 0);
			pj_ks (pj, "text", file);
			free (row);
		}
		pj_end (pj);
	}
	free (subst);
	return true;
}

static bool print_addrinfo2_json(void *user, RBinAddrline *item) {
	FilterStruct *fs = (FilterStruct *)user;
	ut64 offset = item->addr;
	if (!offset || offset == UT64_MAX) {
		return true;
	}
#if 0
	if (colonpos && (fs->filter_offset == UT64_MAX || fs->filter_offset == offset)) {
		if (fs->filter_format) {
			*colonpos = ':';
	//		r_cons_printf (core->cons, "CL %s %s\n", k, subst);
		} else {
			*colonpos = 0;
	//		r_cons_printf (core->cons, "file: %s\nline: %s\naddr: 0x%08"PFMT64x"\n", subst, colonpos + 1, offset);
		}
		fs->filter_count++;
	}
#endif
	const char *file = item->file;
	int line = item->line;
	PJ *pj = fs->pj;
	if (pj) {
		pj_o (pj);
		pj_ks (pj, "file", item->file);
		pj_kn (pj, "line", item->line);
		if (item->column > 0) {
			pj_kn (pj, "column", item->column);
		}
		pj_kn (pj, "addr", item->addr);
		const char *cached_existance = sdb_const_get (fs->fscache, file, NULL);
		bool file_exists = false;
		if (cached_existance) {
			file_exists = !strcmp (cached_existance, "1");
		} else {
			if (r_file_exists (file)) {
				sdb_set (fs->fscache, file, "1", 0);
			} else {
				sdb_set (fs->fscache, file, "0", 0);
			}
		}
		if (file_exists) {
			char *row = r_file_slurp_line (file, line, 0);
			pj_ks (pj, "text", file);
			free (row);
		}
		pj_end (pj);
	}
	return true;
}

static bool print_addrinfo2(void *user, RBinAddrline *item) {
	FilterStruct *fs = (FilterStruct*)user;
	ut64 offset = item->addr;
	if (!offset || offset == UT64_MAX) {
		return true;
	}
	if (fs->filter_offset == UT64_MAX || fs->filter_offset == offset) {
		if (fs->filter_format) {
			// TODO add column if defined
			r_cons_printf (fs->core->cons, "'CL 0x%08"PFMT64x" %s:%d\n", item->addr, item->file, item->line);
		} else {
			r_cons_printf (fs->core->cons, "file: %s\nline: %d\ncolu: %d\naddr: 0x%08"PFMT64x"\n",
				item->file, item->line, item->column, item->addr);
		}
		fs->filter_count++;
	}
	// TODO: return false if filter_offset is found ?

	return true;
}

// R2_600 - DEPRECATE
static bool print_addrinfo(void *user, const char *k, const char *v) {
	FilterStruct *fs = (FilterStruct*)user;
	ut64 offset = sdb_atoi (k);
	if (!offset || offset == UT64_MAX) {
		return true;
	}
	char *subst = strdup (v);
	char *colonpos = strchr (subst, '|');
	if (!colonpos) {
		colonpos = strchr (subst, ':'); // : for shell and | for db.. imho : everywhere
	}
	if (!colonpos) {
		r_cons_printf (fs->core->cons, "%s\n", subst);
	} else if (fs->filter_offset == UT64_MAX || fs->filter_offset == offset) {
		if (fs->filter_format) {
			*colonpos = ':';
			r_cons_printf (fs->core->cons, "'CL %s %s\n", k, subst);
		} else {
			*colonpos++ = 0;
			int line = atoi (colonpos);
			int colu = 0;
			char *columnpos = strchr (colonpos, '|');
			if (columnpos) {
				*columnpos ++ = 0;
				colu = atoi (columnpos);
			}
			r_cons_printf (fs->core->cons, "file: %s\nline: %d\ncolu: %d\naddr: 0x%08"PFMT64x"\n",
				subst, line, colu, offset);
		}
		fs->filter_count++;
	}
	free (subst);

	return true;
}

static int cmd_meta_add_fileline(RBinFile *bf, const char *fileline, ut64 offset) {
#if 1
	char *file = strdup (fileline);
	char *line = strchr (file, ':');
	if (line) {
		*line++ = 0;
	}
	RBinAddrline item = {
		.addr = offset,
		.file = file,
		.line = line? atoi (line): 0,
	};
	bf->addrline.al_add (&bf->addrline, item);
	free (file);
#else
	Sdb *s = bf->sdb_addrinfo;
	char aoffset[SDB_NUM_BUFSZ];
	char *aoffsetptr = sdb_itoa (offset, 16, aoffset, sizeof (aoffset));
	if (!aoffsetptr) {
		return -1;
	}
	if (!sdb_add (s, aoffsetptr, fileline, 0)) {
		sdb_set (s, aoffsetptr, fileline, 0);
	}
	if (!sdb_add (s, fileline, aoffsetptr, 0)) {
		sdb_set (s, fileline, aoffsetptr, 0);
	}
#endif
	return 0;
}

static int cmd_meta_lineinfo(RCore *core, const char *input) {
	int ret;
	ut64 offset = UT64_MAX; // use this as error value
	bool remove = false;
	bool use_json = false;
	int all = false;
	const char *p = input;
	char *file_line = NULL;

	FilterStruct fs = { core, UT64_MAX, 0, 0, NULL };

	if (*p == '?') {
		r_core_cmd_help (core, help_msg_CL);
		return 0;
	}
	if (*p == 'L') { // "CLL"
		if (p[1] == 'f') { // "CLLf"
			r_core_cmd0 (core, "CLL@@i");
			// same as CLL@@i = r_core_cmd0 (core, "list");
			return 0;
		}
		ut64 at = core->addr;
		if (p[1] == ' ') {
			at = r_num_get (core->num, p + 2);
		}
		char *text = r_bin_addrline_tostring (core->bin, at, 0);
		if (R_STR_ISNOTEMPTY (text)) {
			r_cons_printf (core->cons, "0x%08"PFMT64x"  %s\n", at, text);
		}
		free (text);
		return 0;
	}
	if (*p == 'f') { // "CLf"
		int retries = 5;
		ut64 addr = core->addr;
		if (p[1] == ' ') {
			addr = r_num_math (core->num, p + 1);
		}
retry:
		;
		char *s = r_bin_addrline_tostring (core->bin, addr, 3);
		if (!s) {
			RAnalOp *op = r_core_anal_op (core, addr, 0);
			if (op) {
				addr += op->size;
				r_anal_op_free (op);
				if (retries-- > 0) {
					goto retry;
				}
			}
		}
		if (s) {
			r_str_after (s, ':');
			r_cons_println (core->cons, s);
			free (s);
			r_core_return_code (core, 0);
		} else {
			r_core_return_code (core, 1);
		}
		return 0;
	}
	if (*p == '-') { // "CL-"
		p++;
		remove = true;
	}
	if (*p == 'j') { // "CLj"
		p++;
		use_json = true;
	}
	if (*p == '.') { // "CL."
		p++;
		offset = core->addr;
	}
	if (*p == '+') { // "CL+"
		offset = core->addr;
		p = r_str_trim_head_ro (p + 1);
		RBinFile *bf = r_bin_cur (core->bin);
		if (bf) {
			ret = cmd_meta_add_fileline (bf, p, offset);
		}
		return 0;
	}
	if (*p == ' ') { // "CL "
		p = r_str_trim_head_ro (p + 1);
		char *arg = strchr (p, ' ');
		if (!arg) {
			offset = r_num_math (core->num, p);
			p = "";
		}
	} else if (*p == '*') {
		p++;
		all = true;
		fs.filter_format = '*';
	} else {
		fs.filter_format = 0;
	}
	if (all && core->bin->cur) {
		if (remove) {
			r_bin_addrline_reset (core->bin);
		} else {
			if (core->bin->cur && core->bin->cur->addrline.used) {
				r_bin_addrline_foreach (core->bin, print_addrinfo2, &fs);
			} else {
				sdb_foreach (core->bin->cur->sdb_addrinfo, print_addrinfo, &fs);
			}
		}
		return 0;
	}

	p = r_str_trim_head_ro (p);
	char *myp = strdup (p);
	char *sp = strchr (myp, ' ');
	if (sp) {
		*sp = 0;
		sp++;
		if (offset == UT64_MAX) {
			offset = r_num_math (core->num, myp);
		}

		char *pheap = NULL;
		if (r_str_startswith (sp, "base64:")) {
			int len = 0;
			ut8 *o = sdb_decode (sp + 7, &len);
			if (!o) {
				R_LOG_ERROR ("Invalid base64");
				return 0;
			}
			sp = pheap = (char *)o;
		}
		RBinFile *bf = r_bin_cur (core->bin);
		if (bf) {
			// R_LOG_ERROR ("deprecated way to add addrinfo metadata");
			ret = cmd_meta_add_fileline (bf, sp, offset);
		} else {
			R_LOG_TODO ("Support global SdbAddrinfo or dummy rbinfile to handle this case");
			ret = 0;
		}
		free (file_line);
		free (myp);
		free (pheap);
		return ret;
	}
	free (myp);
	if (remove) {
		r_bin_addrline_reset_at (core->bin, offset);
	} else {
		// taken from r2 // TODO: we should move this addrinfo sdb logic into RBin.. use HT
		fs.filter_offset = offset;
		fs.filter_count = 0;
		fs.fscache = sdb_new0 ();
		PJ *pj = NULL;
		RBinFile *bf = r_bin_cur (core->bin);
		if (use_json) {
			pj = r_core_pj_new (core);
			fs.pj = pj;
			pj_a (pj);
			if (!r_bin_addrline_foreach (core->bin, print_addrinfo2_json, &fs)) {
				if (bf && bf->sdb_addrinfo) {
					sdb_foreach (bf->sdb_addrinfo, print_addrinfo_json, &fs);
				}
			}
		} else {
			if (!r_bin_addrline_foreach (core->bin, print_addrinfo2, &fs)) {
				if (bf && bf->sdb_addrinfo) {
					sdb_foreach (bf->sdb_addrinfo, print_addrinfo, &fs);
				}
			}
		}
		if (fs.filter_count == 0) {
			print_meta_offset (core, offset, pj);
		}
		if (use_json) {
			pj_end (pj);
			char *s = pj_drain (pj);
			if (s) {
				r_cons_printf (core->cons, "%s\n", s);
				free (s);
			}
		}
		sdb_free (fs.fscache);
	}
	return 0;
}

static int cmd_meta_comment(RCore *core, const char *input) {
	ut64 addr = core->addr;
	switch (input[1]) {
	case '?':
		r_core_cmd_help (core, help_msg_CC);
		break;
	case ',': // "CC,"
		{
			RTable *t = r_core_table_new (core, "meta");
			r_meta_print_list_all (core->anal, R_META_TYPE_COMMENT, ',', input + 2, t);
		}
		break;
	case 'F': // "CC,"
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_CC, "CCF");
		} else if (input[2] == ' ') {
			const char *fn = input + 2;
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			fn = r_str_trim_head_ro (fn);
			if (R_STR_ISNOTEMPTY (comment)) {
				// append filename in current comment
				char *nc = r_str_newf ("%s ,(%s)", comment, fn);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, nc);
				free (nc);
			} else {
				char *newcomment = r_str_newf (",(%s)", fn);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, newcomment);
				free (newcomment);
			}
		} else {
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			if (R_STR_ISNOTEMPTY (comment)) {
				char *cmtfile = r_str_between (comment, ",(", ")");
				if (R_STR_ISNOTEMPTY (cmtfile)) {
					char *cwd = getcommapath (core);
					r_cons_printf (core->cons, "%s"R_SYS_DIR"%s\n", cwd, cmtfile);
					free (cwd);
				}
				free (cmtfile);
			}
		}
		break;
	case '.': // "CC."
		{
			ut64 at = input[2]? r_num_math (core->num, input + 2): addr;
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, at);
			if (R_STR_ISNOTEMPTY (comment)) {
				r_cons_println (core->cons, comment);
			}
		}
		break;
	case 0: // "CC"
		r_meta_print_list_all (core->anal, R_META_TYPE_COMMENT, 0, NULL, NULL);
		break;
	case 'f': // "CCf"
		switch (input[2]) {
		case '-': // "CCf-"
			{
				ut64 arg = r_num_math (core->num, input + 2);
				if (!arg) {
					arg = core->addr;
				}
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, arg, 0);
				if (fcn) {
					RAnalBlock *bb;
					RListIter *iter;
					r_list_foreach (fcn->bbs, iter, bb) {
						int i;
						for (i = 0; i < bb->size; i++) {
							ut64 addr = bb->addr + i;
							r_meta_del (core->anal, R_META_TYPE_COMMENT, addr, 1);
						}
					}
				}
			}
			break;
		case ',': // "CCf,"
			{
				RTable *t = r_core_table_new (core, "comments");
				r_meta_print_list_in_function (core->anal, R_META_TYPE_COMMENT, ',', core->addr, input + 3, t);
			}
			break;
		case 'j': // "CCfj"
			r_meta_print_list_in_function (core->anal, R_META_TYPE_COMMENT, 'j', core->addr, NULL, NULL);
			break;
		case '*': // "CCf*"
			r_meta_print_list_in_function (core->anal, R_META_TYPE_COMMENT, 1, core->addr, NULL, NULL);
			break;
		default:
			r_meta_print_list_in_function (core->anal, R_META_TYPE_COMMENT, 0, core->addr, NULL, NULL);
			break;
		}
		break;
	case 'j': // "CCj"
		r_meta_print_list_all (core->anal, R_META_TYPE_COMMENT, 'j', input + 2, NULL);
		break;
	case '!': // "CC!"
		{
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			char *out = r_core_editor (core, NULL, comment);
			if (out) {
				r_str_ansi_strip (out);
				//r_meta_set (core->anal->meta, R_META_TYPE_COMMENT, addr, 0, out);
				r_core_cmd_call_at (core, addr, "CC-");
				//r_meta_del (core->anal->meta, input[0], addr, addr+1);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, out);
				free (out);
			}
		}
		break;
	case '+':
	case ' ':
		{
		const char *arg = r_str_trim_head_ro (input + 2);
		const char *newcomment = arg;
		if (r_str_startswith (arg, "base64:")) {
			char *s = (char *)sdb_decode (arg + 7, NULL);
			if (s) {
				newcomment = s;
			} else {
				R_LOG_ERROR ("Invalid base64 string");
				break;
			}
		}
		const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
		char *nc = strdup (newcomment);
		r_str_unescape (nc);
		r_str_ansi_strip (nc);
		if (comment) {
			char *text = r_str_newf ("%s %s", comment, nc);
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, text);
			free (text);
		} else {
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, nc);
			if (r_config_get_b (core->config, "cmd.undo")) {
				char *a = r_str_newf ("'CC-0x%08"PFMT64x, addr);
				char *b = r_str_newf ("'@0x%08"PFMT64x"'CC %s", addr, nc);
				RCoreUndo *uc = r_core_undo_new (core->addr, b, a);
				r_core_undo_push (core, uc);
				free (a);
				free (b);
			}
		}
		free (nc);
		}
		break;
	case '*': // "CC*"
		r_meta_print_list_all (core->anal, R_META_TYPE_COMMENT, 1, NULL, NULL);
		break;
	case '-': // "CC-"
		if (input[2] == '*') { // "CC-*"
			r_meta_del (core->anal, R_META_TYPE_COMMENT, UT64_MAX, UT64_MAX);
		} else if (input[2]) { // "CC-$$+32"
			ut64 arg = r_num_math (core->num, input + 2);
			r_meta_del (core->anal, R_META_TYPE_COMMENT, arg, 1);
		} else { // "CC-"
			r_meta_del (core->anal, R_META_TYPE_COMMENT, core->addr, 1);
		}
		break;
	case 'u': // "CCu"
		{
		const char *arg = input + 2;
		while (*arg && *arg == ' ') {
			arg++;
		}
		char *newcomment = r_str_startswith (arg, "base64:")
			? (char *)sdb_decode (arg + 7, NULL): strdup (arg);
		if (newcomment) {
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			if (!comment || (comment && !strstr (comment, newcomment))) {
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, newcomment);
			}
			free (newcomment);
		}
		}
		break;
	case 'a': // "CCa"
		{
		char *s = strchr (input, ' ');
		if (s) {
			s = strdup (s + 1);
		} else {
			r_core_cmd_help_match (core, help_msg_CC, "CCa");
			return false;
		}
		char *p = strchr (s, ' ');
		if (p) {
			*p++ = 0;
		}
		ut64 addr;
		if (input[2] == '-') {
			if (input[3]) {
				addr = r_num_math (core->num, input+3);
				r_meta_del (core->anal,
						R_META_TYPE_COMMENT,
						addr, 1);
			} else {
				r_core_cmd_help_match (core, help_msg_CC, "CCa");
			}
			free (s);
			return true;
		}
		addr = r_num_math (core->num, s);
		// Comment at
		if (p) {
			if (input[2] == '+') {
				const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
				if (comment) {
					char *text = r_str_newf ("%s\n%s", comment, p);
					r_meta_set (core->anal, R_META_TYPE_COMMENT, addr, 1, text);
					free (text);
				} else {
					r_meta_set (core->anal, R_META_TYPE_COMMENT, addr, 1, p);
				}
			} else {
				r_meta_set (core->anal, R_META_TYPE_COMMENT, addr, 1, p);
			}
		} else {
			r_core_cmd_help_match (core, help_msg_CC, "CCa");
		}
		free (s);
		return true;
		}
	}
	return true;
}

static int cmd_meta_vartype_comment(RCore *core, const char *input) {
	ut64 addr = core->addr;
	switch (input[1]) {
	case '?': // "Ct?"
		r_core_cmd_help (core, help_msg_Ct);
		break;
	case 0: // "Ct"
		r_meta_print_list_all (core->anal, R_META_TYPE_VARTYPE, 0, NULL, NULL);
		break;
	case ' ': // "Ct <vartype comment> @ addr"
		{
		const char* newcomment = r_str_trim_head_ro (input + 2);
		const char *comment = r_meta_get_string (core->anal, R_META_TYPE_VARTYPE, addr);
		char *nc = strdup (newcomment);
		r_str_unescape (nc);
		if (comment) {
			char *text = r_str_newf ("%s %s", comment, nc);
			if (R_LIKELY (text)) {
				r_meta_set_string (core->anal, R_META_TYPE_VARTYPE, addr, text);
				free (text);
			}
		} else {
			r_meta_set_string (core->anal, R_META_TYPE_VARTYPE, addr, nc);
		}
		free (nc);
		}
		break;
	case '.': // "Ct. @ addr"
		{
		ut64 at = input[2]? r_num_math (core->num, input + 2): addr;
		const char *comment = r_meta_get_string (core->anal, R_META_TYPE_VARTYPE, at);
		if (R_STR_ISNOTEMPTY (comment)) {
			r_cons_println (core->cons, comment);
		}
		}
		break;
	case '-': // "Ct-"
		r_meta_del (core->anal, R_META_TYPE_VARTYPE, core->addr, 1);
		break;
	default:
		r_core_cmd_help (core, help_msg_Ct);
		break;
	}
	return true;
}

typedef struct {
	RCore *core;
	ut64 addr;
	ut8 *buf;
	int bufsz;
} StringSearchOptions;

static int cb_strhit(RSearchKeyword * R_NULLABLE kw, void *user, ut64 where) {
	StringSearchOptions *sso = (StringSearchOptions*)user;
	if (where - sso->addr >= sso->bufsz) {
		r_core_cmd_call_at (sso->core, where, "Cz");
	} else {
		const char *name = (const char *)(sso->buf + (where - sso->addr));
		const size_t maxlen = sso->bufsz - (where - sso->addr);
		char *hname = r_str_ndup (name, maxlen);
		const size_t n = strlen (hname) + 1;
		r_meta_set (sso->core->anal, R_META_TYPE_STRING, where, n, hname);
		free (hname);
	}
	return true;
}

static int cmd_meta_others(RCore *core, const char *input) {
	char *t = 0, *p, *p2, name[256] = {0};
	int n, repeat = 1;
	ut64 addr = core->addr;

	int type = input[0];
	if (!type) {
		return 0;
	}
	int subtype = input[1];
	if (type == 's' && subtype == 'z') {
		subtype = 0;
	}

	switch (subtype) {
	case '?':
		switch (input[0]) {
		case 'f': // "Cf?"
			r_core_cmd_help_match (core, help_msg_C, "Cf");
			r_cons_println (core->cons,
				"'sz' indicates the byte size taken up by struct.\n"
				"'fmt' is a 'pf?' style format string. It controls only the display format.\n\n"
				"You may wish to have 'sz' != sizeof (fmt) when you have a large struct\n"
				"but have only identified specific fields in it. In that case, use 'fmt'\n"
				"to show the fields you know about (perhaps using 'skip' fields), and 'sz'\n"
				"to match the total struct size in mem.\n");
			break;
		case 's': // "Cs?"
			r_core_cmd_help (core, help_msg_Cs);
			break;
		default:
			r_cons_println (core->cons, "See C?");
			break;
		}
		break;
	case '-': // "Cf-", "Cd-", ...
		switch (input[2]) {
		case '*': // "Cf-*", "Cd-*", ...
			r_meta_del (core->anal, input[0], 0, UT64_MAX);
			break;
		case ' ':
			p2 = strchr (input + 3, ' ');
			if (p2) {
				ut64 i;
				ut64 size = r_num_math (core->num, input + 3);
				ut64 rep = r_num_math (core->num, p2 + 1);
				ut64 cur_addr = addr;
				if (!size) {
					break;
				}
				for (i = 0; i < rep && UT64_MAX - cur_addr > size; i++, cur_addr += size) {
					r_meta_del (core->anal, input[0], cur_addr, size);
				}
				break;
			} else {
				addr = r_num_math (core->num, input + 3);
				/* fallthrough */
			}
		default:
			r_meta_del (core->anal, input[0], addr, 1);
			break;
		}
		break;
	case '*': // "Cf*", "Cd*", ...
		r_meta_print_list_all (core->anal, input[0], 1, NULL, NULL);
		break;
	case 'j': // "Cfj", "Cdj", ...
		r_meta_print_list_all (core->anal, input[0], 'j', NULL, NULL);
		break;
	case '!': // "Cf!", "Cd!", ...
		{
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			char *out = r_core_editor (core, NULL, comment);
			if (out) {
				r_str_ansi_strip (out);
				//r_meta_set (core->anal->meta, R_META_TYPE_COMMENT, addr, 0, out);
				r_core_cmd_call_at (core, addr, "CC-");
				//r_meta_del (core->anal->meta, input[0], addr, addr+1);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, out);
				free (out);
			}
		}
		break;
	case '.': // "Cf.", "Cd.", ...
		if (input[2] == '.') { // "Cs.."
			ut64 size;
			RAnalMetaItem *mi = r_meta_get_at (core->anal, addr, type, &size);
			if (mi) {
				r_meta_print (core->anal, mi, addr, size, input[3], NULL, NULL, false);
			}
			break;
		} else if (input[2] == 'j') { // "Cs.j"
			ut64 size;
			RAnalMetaItem *mi = r_meta_get_at (core->anal, addr, type, &size);
			if (mi) {
				r_meta_print (core->anal, mi, addr, size, input[2], NULL, NULL, false);
				r_cons_newline (core->cons);
			}
			break;
		}
		ut64 size;
		RAnalMetaItem *mi = r_meta_get_at (core->anal, addr, type, &size);
		if (!mi) {
			break;
		}
		if (type == 's') {
			char *esc_str;
			bool esc_bslash = core->print->esc_bslash;
			switch (mi->subtype) {
			case R_STRING_ENC_UTF8:
				esc_str = r_str_escape_utf8 (mi->str, false, esc_bslash);
				break;
			case 0: // temporary legacy workaround
				esc_bslash = false;
				// falltrhru
			default:
				esc_str = r_str_escape_latin1 (mi->str, false, esc_bslash, false);
				break;
			}
			if (esc_str) {
				r_cons_printf (core->cons, "\"%s\"\n", esc_str);
				free (esc_str);
			} else {
				r_cons_println (core->cons, "<oom>");
			}
		} else if (type == 'd') {
			r_cons_printf (core->cons, "%"PFMT64u"\n", size);
		} else {
			r_cons_println (core->cons, mi->str);
		}
		break;
	case 's': // "Css"
		{
			ut64 range = UT64_MAX;
			if (input[0] && input[1] && input[2]) {
				range = r_num_math (core->num, input + 3);
			}
			if (range == UT64_MAX || range == 0) {
				// get cursection size
				RBinSection *s = r_bin_get_section_at (r_bin_cur_object (core->bin), core->addr, true);
				if (s) {
					range = s->vaddr + s->vsize - core->addr;
				}
				// TODO use debug maps if cfg.debug=true?
			}
			if (range == UT64_MAX || range == 0) {
				R_LOG_ERROR ("Invalid memory range passed to Css");
			} else if (range > 32 * 1024 * 1024) {
				R_LOG_ERROR ("Range is too large");
			} else {
				ut8 *buf = malloc (range + 1);
				if (buf) {
					buf[range] = 0;
					const ut64 addr = core->addr;
					const int minstr = r_config_get_i (core->config, "bin.str.min");
					const int maxstr = r_config_get_i (core->config, "bin.str.max");
					r_core_cmdf (core, "Cz@0x%08"PFMT64x, addr);
					// maps are not yet set
					free (r_core_cmd_str (core, "o;om")); // wtf?
					if (!r_io_read_at (core->io, addr, buf, range)) {
						R_LOG_ERROR ("Cannot read %d", range);
					}
					RSearch *ss = r_search_new (R_SEARCH_STRING);
					r_search_set_string_limits (ss, minstr, maxstr);
					StringSearchOptions sso = {
						.addr = addr,
						.core = core,
						.buf = buf,
						.bufsz = range
					};
					// r_print_hexdump (core->print, addr, buf, range, 8,1,1);
					r_search_set_callback (ss, cb_strhit, &sso);
					r_search_begin (ss);
					r_search_update (ss, addr, buf, range);
					r_search_free (ss);
					free (buf);
				} else {
					R_LOG_ERROR ("Cannot allocate");
				}
#if 0
				r_core_cmdf (core, "/z 8 100@0x%08"PFMT64x"@e:search.in=range@e:search.from=0x%"PFMT64x"@e:search.to=0x%"PFMT64x,
						core->addr, core->addr, core->addr + range);
				r_core_cmd0 (core, "Csz @@ hit*;f-hit*");
#else
#endif
			}
		}
		break;
	case ' ': // "Cf", "Cd", ...
	case '\0':
	case 'g':
	case 'a':
	case '1':
	case 'w':
	case 'p':
	case 'b':
	case 'r':
	case '2':
	case '4':
	case '8': // "Cd8"
		if (type == 'd') {  // "Cd4"
			switch (input[1]) {
			case '1':
			case '2':
			case '4':
			case '8':
				input--;
				break;
			}
		}
		if (type == 'z') {
			type = 's';
		} else {
			if (!input[1] && !core->tmpseek) {
				r_meta_print_list_all (core->anal, type, 0, NULL, NULL);
				break;
			}
		}
		int len = (!input[1] || input[1] == ' ') ? 2 : 3;
		if (strlen (input) > len) {
			char *rep = strchr (input + len, '[');
			if (!rep) {
				rep = strchr (input + len, ' ');
			}
			if (*input == 'd') {
				if (rep) {
					repeat = r_num_math (core->num, rep + 1);
				}
			}
		}
		int repcnt = 0;
		if (repeat < 1) {
			repeat = 1;
		}
		while (repcnt < repeat) {
			int off = (!input[1] || input[1] == ' ') ? 1 : 2;
			t = strdup (r_str_trim_head_ro (input + off));
			p = NULL;
			n = 0;
			r_str_ncpy (name, t, sizeof (name));
			if (type != 'C') {
				n = r_num_math (core->num, t);
				if (type == 'f') { // "Cf"
					p = strchr (t, ' ');
					if (p) {
						p = (char *)r_str_trim_head_ro (p);
						if (*p == '.') {
							const char *realformat = r_print_format_byname (core->print, p + 1);
							if (realformat) {
								p = (char *)realformat;
							} else {
								R_LOG_WARN ("Cannot resolve format '%s'", p + 1);
								break;
							}
						}
						if (n < 1) {
							n = r_print_format_struct_size (core->print, p, 0, 0);
							if (n < 1) {
								R_LOG_WARN ("Cannot resolve struct size for '%s'", p);
								n = 32; //
							}
						}
						// make sure we do not overflow on r_print_format
						if (n > core->blocksize) {
							n = core->blocksize;
						}
						int r = r_print_format (core->print, addr, core->block,
							n, p, 0, NULL, NULL);
						if (r < 0) {
							n  = -1;
						}
					} else {
						r_core_cmd_help_match (core, help_msg_C, "Cf");
						break;
					}
				} else if (type == 's') { // "Cs"
					int name_len = 0;
					// TODO 256 is the limit. and that shouldnt be a hard limit
					if (input[1] == 'w' || input[1] == 'g') { // "Csw" "Csg"
						int i, j;
						char tmp[256] = {0};
						(void)r_io_read_at (core->io, addr, (ut8*)tmp, sizeof (tmp) - 3);
						name_len = r_str_nlen_w (tmp, sizeof (tmp) - 3);
						// handle wide strings
						for (i = 0, j = 0; i < sizeof (name); i++, j++) {
							name[i] = tmp[j];
							if (!tmp[j]) {
								break;
							}
							if (!tmp[j + 1]) {
								if (j + 3 < sizeof (tmp)) {
									if (tmp[j + 3]) {
										break;
									}
								}
								j++;
							}
						}
						name[sizeof (name) - 1] = '\0';
					} else if (input[1] == 'p') { // "Csp" // pascal string
						// TODO: add support for wide pascal strings
						ut8 fourbuf[4];
						(void)r_io_read_at (core->io, addr, (ut8*)fourbuf, sizeof (fourbuf));
						name_len = 0;
						if (n == 0 || n > 4) {
							// autoguess
							if (!fourbuf[0] && !fourbuf[1]) {
								n = 4;
							} else if (!fourbuf[1]) {
								n = 2;
							} else {
								n = 1;
							}
						}
						switch (n) {
						case 4:
							name_len = r_read_le32 (fourbuf);
							break;
						case 2:
							name_len = r_read_le16 (fourbuf);
							break;
						case 1:
							name_len = fourbuf[0];
							break;
						case -4:
							name_len = r_read_be32 (fourbuf);
							break;
						case -2:
							name_len = r_read_be16 (fourbuf);
							break;
						case -1:
							name_len = fourbuf[0];
							break;
						default:
							R_LOG_ERROR ("Invalid pascal length field size. Must be -4, -2, -1, 1, 2, 4");
							return false;
						}
						if (name_len >= 0 && name_len < 256) {
							char tmp[256] = {0};
							const size_t delta = R_ABS (n);
							(void)r_io_read_at (core->io, addr + delta, (ut8*)tmp, sizeof (tmp) - 3);
							r_str_ncpy (name, tmp, name_len);
							// TODO: use api instead: r_meta_set (core->anal, 'd', addr, delta, name);
							r_core_cmdf (core, "Cd%d@0x%08"PFMT64x, (int)delta, addr);
							{
								char *tmp = r_name_filter_dup (name);
								r_core_cmdf (core, "f str.pascal.%s@0x%08"PFMT64x, tmp, addr);
								free (tmp);
							}
							addr += delta;
							n = name_len;
						} else {
							R_LOG_ERROR ("Invalid pascal string value length (%d)", name_len);
							return false;
						}
					} else if (input[1] == 'a' || input[1] == '8') {
						// "Cs8" "Csa" // utf8 and ascii strings handling
						(void)r_io_read_at (core->io, addr, (ut8*)name, sizeof (name) - 1);
						name[sizeof (name) - 1] = '\0';
						name_len = strlen (name);
					} else if (input[1] == 0 || input[1] == ' ') {
						// same as Cs8 or Csa
						(void)r_io_read_at (core->io, addr, (ut8*)name, sizeof (name) - 1);
						name[sizeof (name) - 1] = '\0';
						name_len = strlen (name);
					} else {
						R_LOG_WARN ("Unknown Cs subcommand %c", input[1]);
						(void)r_io_read_at (core->io, addr, (ut8*)name, sizeof (name) - 1);
						name[sizeof (name) - 1] = '\0';
						name_len = strlen (name);
					}
					if (n == 0) {
						n = name_len + 1;
					} else {
						if (n > 0 && n < name_len) {
							name[n] = 0;
						}
					}
				}
				if (n < 1) {
					/* invalid length, do not insert into db */
					return false;
				}
				if (!*t || n > 0) {
					p = strchr (t, ' ');
					if (p) {
						*p++ = '\0';
						p = (char *)r_str_trim_head_ro (p);
						r_str_ncpy (name, p, sizeof (name));
					} else {
						if (type != 'b' && type != 's') {
							RFlagItem *fi = r_flag_get_in (core->flags, addr);
							if (fi) {
								r_str_ncpy (name, fi->name, sizeof (name));
							}
						}
					}
				}
			}
			if (!n) {
				n++;
			}
			if (type == 's') {
				switch (input[1]) {
				case 'a':
				case '8':
				case 'w':
					subtype = input[1];
					break;
				default:
					subtype = R_STRING_ENC_GUESS;
				}
				r_meta_set_with_subtype (core->anal, type, subtype, addr, n, name);
			} else {
				r_meta_set (core->anal, type, addr, n, name);
			}
			free (t);
			repcnt ++;
			addr += n;
		}
		// r_meta_cleanup (core->anal->meta, 0LL, UT64_MAX);
		break;
	default:
		R_LOG_ERROR ("Missing space after CC");
		break;
	}

	return true;
}

static void comment_var_help(RCore *core, char type) {
	switch (type) {
	case 'b':
		r_core_cmd_help (core, help_msg_Cvb);
		break;
	case 's':
		r_core_cmd_help (core, help_msg_Cvs);
		break;
	case 'r':
		r_core_cmd_help (core, help_msg_Cvr);
		break;
	case '?':
		r_cons_printf (core->cons, "See Cvb?, Cvs? and Cvr?\n");
	}
}

static void cmd_Cv(RCore *core, const char *input) {
	// TODO enable base64 and make it the default for C*
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
	char *oname = NULL, *name = NULL;

	if (!input[0] || input[1] == '?' || (input[0] != 'b' && input[0] != 'r' && input[0] != 's')) {
		comment_var_help (core, input[0]);
		return;
	}
	if (!fcn) {
		R_LOG_ERROR ("Can't find function here");
		return;
	}
	oname = name = r_str_trim_dup (input + 1);
	switch (input[1]) {
	case '*': // "Cv*"
	case '\0': { // "Cv"
		void **it;
		char kind = input[0];
		r_pvector_foreach (&fcn->vars, it) {
			RAnalVar *var = *it;
			if (var->kind != kind || !var->comment) {
				continue;
			}
			if (input[1]) {
				char *b64 = sdb_encode ((const ut8 *)var->comment, strlen (var->comment));
				if (!b64) {
					continue;
				}
				r_cons_printf (core->cons, "'@0x%08"PFMT64x"'Cv%c %s base64:%s\n", fcn->addr, kind, var->name, b64);
				free (b64);
			} else {
				r_cons_printf (core->cons, "%s : %s\n", var->name, var->comment);
			}
		}
		}
		break;
	case ' ': { // "Cv "
		char *comment = strchr (name, ' ');
		char *heap_comment = NULL;
		if (comment) { // new comment given
			if (*comment) {
				*comment++ = 0;
			}
			if (!strncmp (comment, "base64:", 7)) {
				heap_comment = (char *)sdb_decode (comment + 7, NULL);
				comment = heap_comment;
			}
		}
		RAnalVar *var = r_anal_function_get_var_byname (fcn, name);
		if (!var) {
			const int idx = (int)strtol (name, NULL, 0);
			var = r_anal_function_get_var (fcn, input[0], idx);
		}
		if (var) {
			if (var->comment) {
				if (R_STR_ISNOTEMPTY (comment)) {
					char *text = r_str_newf ("%s\n%s", var->comment, comment);
					free (var->comment);
					var->comment = text;
				} else {
					r_cons_println (core->cons, var->comment);
				}
			} else if (R_STR_ISNOTEMPTY (comment)) {
				var->comment = strdup (comment);
			}
		} else {
			R_LOG_ERROR ("can't find variable at given offset");
		}
		free (heap_comment);
		}
		break;
	case '-': { // "Cv-"
		name++;
		r_str_trim (name);
		RAnalVar *var = r_anal_function_get_var_byname (fcn, name);
		if (!var) {
			int idx = (int)strtol (name, NULL, 0);
			var = r_anal_function_get_var (fcn, input[0], idx);
		}
		if (!var) {
			R_LOG_ERROR ("can't find variable at given offset");
			break;
		}
		free (var->comment);
		var->comment = NULL;
		break;
	}
	case '!': { // "Cv!"
		char *comment;
		name++;
		r_str_trim (name);
		RAnalVar *var = r_anal_function_get_var_byname (fcn, name);
		if (!var) {
			R_LOG_ERROR ("can't find variable named `%s`", name);
			break;
		}
		comment = r_core_editor (core, NULL, var->comment);
		if (comment) {
			free (var->comment);
			var->comment = comment;
		}
		}
		break;
	}
	free (oname);
}

static int cmd_meta(void *data, const char *input) {
	RCore *core = (RCore*)data;
	RAnalFunction *f;
	RSpaces *ms;
	int i;

	switch (*input) {
	case 'v': // "Cv"
		cmd_Cv (core, input + 1);
		break;
	case '\0': // "C"
		r_meta_print_list_all (core->anal, R_META_TYPE_ANY, 0, NULL, NULL);
		break;
	case ',': // "C,"
		r_meta_print_list_all (core->anal, R_META_TYPE_ANY, *input, input + 1, NULL);
		break;
	case 'j': // "Cj"
	case '*': { // "C*"
		if (input[1] == '.') {
			r_meta_print_list_at (core->anal, core->addr, *input, input + 2, NULL);
		} else if (input[1]) {
			r_meta_print_list_at (core->anal, core->addr, *input, input + 2, NULL);
		} else {
			r_meta_print_list_all (core->anal, R_META_TYPE_ANY, *input, input + 1, NULL);
		}
		break;
	}
	case '.': { // "C."
		r_meta_print_list_at (core->anal, core->addr, 0, NULL, NULL);
		break;
	}
	case 'L': // "CL"
		cmd_meta_lineinfo (core, input + 1);
		break;
	case 'C': // "CC"
		cmd_meta_comment (core, input);
		break;
	case 't': // "Ct" type analysis commnets
		cmd_meta_vartype_comment (core, input);
		break;
	case 'b': // "Cb" bind addresses
	case 'r': // "Cr" run command
	case 'h': // "Ch" comment
	case 's': // "Cs" string
	case 'z': // "Cz" zero-terminated string
	case 'd': // "Cd" data
	case 'm': // "Cm" magic
	case 'f': // "Cf" formatted
		cmd_meta_others (core, input);
		break;
	case '-': // "C-"
		if (input[1] != '*') {
			i = input[1] ? r_num_math (core->num, input + (input[1] == ' ' ? 2 : 1)) : 1;
			r_meta_del (core->anal, R_META_TYPE_ANY, core->addr, i);
		} else {
			r_meta_del (core->anal, R_META_TYPE_ANY, 0, UT64_MAX);
		}
		break;
	case '?': // "C?"
		r_core_cmd_help (core, help_msg_C);
		break;
	case 'F': // "CF"
		f = r_anal_get_fcn_in (core->anal, core->addr,
			R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		if (f) {
			r_anal_str_to_fcn (core->anal, f, input + 2);
		} else {
			R_LOG_ERROR ("Cannot find function here");
		}
		break;
	case 'S': // "CS"
		ms = &core->anal->meta_spaces;
		/** copypasta from `fs`.. this must be refactorized to be shared */
		switch (input[1]) {
		case '?': // "CS?"
			r_core_cmd_help (core, help_msg_CS);
			break;
		case '+': // "CS+"
			r_spaces_push (ms, input + 2);
			break;
		case 'r': // "CSr"
			if (input[2] == ' ') {
				r_spaces_rename (ms, NULL, input + 2);
			} else {
				r_core_cmd_help_match (core, help_msg_CS, "CSr");
			}
			break;
		case '-': // "CS-"
			if (input[2]) {
				if (input[2] == '*') {
					r_spaces_unset (ms, NULL);
				} else {
					r_spaces_unset (ms, input + 2);
				}
			} else {
				r_spaces_pop (ms);
			}
			break;
		case 'j': // "CSj"
		case '\0': // "CS"
		case '*': // "CS*"
			spaces_list (core, ms, input[1]);
			break;
		case ' ': // "CS "
			r_spaces_set (ms, input + 2);
			break;
		default:
			spaces_list (core, ms, 0);
			break;
		}
		break;
	default:
		r_core_return_invalid_command (core, "C", *input);
		break;
	}
	return true;
}
#endif
