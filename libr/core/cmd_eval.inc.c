/* radare2 - LGPL - Copyright 2009-2025 - pancake */

#if R_INCLUDE_BEGIN

static RCoreHelpMessage help_msg_ecH = {
	"用法 ecH[iw-?]", "", "",
	"ecHi", "[color]", "使用'color'背景高亮显示当前指令",
	"ecHw", "[word] [color]", "使用'color'背景高亮显示当前指令中的'word'",
	"ecH", "", "列出所有高亮规则",
	"ecH.", "", "显示当前偏移处的高亮规则",
	"ecH-", "*", "移除所有高亮提示",
	"ecH-", "", "移除当前指令上的所有高亮",
	NULL
};

static RCoreHelpMessage help_msg_e = {
	"用法:", "e [var[=value]]", "可求值的变量",
	"e", "?asm.bytes", "显示描述",
	"e", "??", "列出带有描述的所有配置变量",
	"e", " a", "获取变量'a'的值",
	"e", " a=b", "将变量'a'设置为'b'值",
#if 0
	// 已注释以避免误导性混淆
	"e var=?", "", "打印变量的所有有效值",
	"e var=??", "", "打印变量的所有有效值及描述",
#endif
	"e.", "a=b", "与'e a=b'相同，但不使用空格",
	"e,", "[table-query]", "以表格格式显示输出",
	"e:", "k=v:k=v:k=v", "逗号或冒号分隔的 k[=v]",
	"e-", "", "重置配置变量",
	"e*", "", "以 r 命令转储配置变量",
	"e!", "a", "反转布尔变量'a'的值",
	"ec", "[?] [k] [color]", "为给定键设置颜色 (提示符、偏移量等)",
	"ee", " [var]", "打开 cfg.editor 更改变量的值",
	"ed", "", "打开编辑器更改 ~/.radare2rc",
	"ed*", "", "显示 ~/.radare2rc 的内容",
	"ed+", "", "向 ~/.radare2rc 添加或设置评估配置行",
	"ed-", "[!]", "删除 ~/.radare2rc (使用 ed-! 无需提示直接删除)",
	"ej", "", "以 JSON 格式列出配置变量",
	"eJ", "", "以详细 JSON 格式列出配置变量",
	"en", "", "列出环境变量",
	"env", " [k[=v]]", "获取/设置环境变量",
	"er", " [key]", "将配置键设置为只读。无法撤销",
	"es", " [space]", "列出所有评估空间 [或键]",
	"et", " [key]", "显示给定配置变量的类型",
	"ev", " [key]", "以详细格式列出配置变量",
	"evj", " [key]", "以详细 JSON 格式列出配置变量",
	NULL
};

static RCoreHelpMessage help_msg_ec = {
	"用法 ec[s?] [key][[=| ]fg] [bg]", "", "",
	"ec", " [key]", "列出所有/键颜色键",
	"ec*", "", "同上，但使用 r2 命令",
	"ecd", "", "设置默认调色板",
	"ecr", "", "设置随机调色板 (另见 scr.randpal)",
	"ecs", "", "显示彩色调色板",
	"ecj", "", "以 JSON 格式显示调色板",
	"ecc", " [prefix]", "以 CSS 格式显示调色板",
	"eco", " [theme]", "如果提供则加载主题 (否则列出可用主题)",
	"ecp", "", "加载上一个颜色主题",
	"ecn", "", "加载下一个颜色主题",
	"ecH", "[?]", "高亮单词或指令",
	"ec", " prompt red", "更改提示符颜色",
	"ec", " prompt red blue", "更改提示符的颜色和背景",
	"变量:", "", "",
	"颜色:", "", "rgb:000, red, green, blue, #ff0000, ...",
	"e scr.color", "=0", "使用更多颜色 (0: 无颜色 1: ansi 16, 2: 256, 3: 16M)",
	"$DATADIR/radare2/cons", "", "~/.local/share/radare2/cons", // XXX 应该是主题
	NULL
};

static RCoreHelpMessage help_msg_eco = {
	"用法: eco[jc] [theme]", "", "加载主题 (参见路径和 dir.prefix)",
	"eco", "", "列出可用主题 (参见 e dir.themes)",
	"eco.", "", "显示当前主题名称",
	"eco*", "", "显示当前主题脚本",
	"eco!", "", "编辑并重新加载当前主题",
	"ecoo", "", "重新加载当前主题",
	"ecoq", "", "列出可用主题但不显示当前主题",
	"ecoj", "", "以 JSON 格式列出可用主题",
	"路径:", "", "",
	"$DATADIR/radare2/cons", "", "~/.local/share/radare2/cons", // XXX 应该是主题
	NULL
};

static void cmd_eval_table(RCore *core, const char *input) {
	const char fmt = *input;
	const char *q = input;
	RTable *t = r_core_table_new (core, "eval");
	RTableColumnType *typeString = r_table_type ("string");
	RTableColumnType *typeBoolean = r_table_type ("bool");
	r_table_add_column (t, typeBoolean, "ro", 0);
	r_table_add_column (t, typeString, "type", 0);
	r_table_add_column (t, typeString, "key", 0);
	r_table_add_column (t, typeString, "value", 0);
	r_table_add_column (t, typeString, "desc", 0);

	RListIter *iter;
	RConfigNode *node;
	r_list_foreach (core->config->nodes, iter, node) {
		r_strf_var (type, 32, "%s", r_config_node_type (node));
		r_strf_var (ro, 32, "%s", r_config_node_is_ro (node)? "ro": "");
		r_table_add_row (t, ro, type, node->name, node->value, node->desc, NULL);
	}
	if (r_table_query (t, q)) {
		char *s = (fmt == 'j')
			? r_table_tojson (t)
			: r_table_tostring (t);
		r_cons_printf (core->cons, "%s\n", s);
		free (s);
	}
	r_table_free (t);
}

static bool nextpal_item(RCore *core, PJ *pj, int mode, const char *file) {
	const char *fn = r_str_lchr (file, '/');
	if (!fn) {
		fn = file;
	}
	switch (mode) {
	case 'j': // json
		pj_s (pj, fn);
		break;
	case 'l': // list
		r_cons_println (core->cons, fn);
		break;
	case 'p': // previous
		// TODO: move logic here
		break;
	case 'n': // next
		if (core->theme && !strcmp (core->theme, "default")) {
			free (core->theme);
			core->theme = strdup (fn);
			core->get_next = false;
		}
		if (core->get_next) {
			free (core->theme);
			core->theme = strdup (fn);
			core->get_next = false;
			return false;
		}
		if (!core->theme) {
			core->theme = strdup (fn);
			return false;
		}
		if (!strcmp (core->theme, fn)) {
			core->get_next = true;
		}
		break;
	}
	return true;
}

static char *get_theme_path(RCore *core, const char *theme_name) {
	// check home directory
	char *home = r_xdg_datadir ("cons");
	char *theme_path = r_file_new (home, theme_name, NULL);
	if (r_file_exists (theme_path)) {
		// TODO read this one
		return theme_path;
	}
	free (theme_path);
	// check system directory
	const char *r2pfx = r_sys_prefix (NULL);
	theme_path = r_file_new (r2pfx, R2_THEMES, theme_name, NULL);
	if (r_file_exists (theme_path)) {
		return theme_path;
	}
	free (theme_path);
	return NULL;
}

static char *get_theme_script(RCore *core, const char *theme_name) {
	if (!strcmp (theme_name, "default")) {
		// reserved name
		return NULL;
	}
	char *theme_path = get_theme_path (core, theme_name);
	if (theme_path) {
		char *theme_script = r_file_slurp (theme_path, NULL);
		free (theme_path);
		return theme_script;
	}
#if WITH_STATIC_THEMES
	const RConsTheme *theme = r_cons_themes ();
	while (theme && theme->name) {
		if (!strcmp (theme->name, theme_name)) {
			return strdup (theme->script);
		}
		theme++;
	}
#endif
	return NULL;
}

static bool cmd_load_theme(RCore *core, const char *_arg) {
	if (!strcmp (_arg, "default")) {
		if (_arg != core->theme) {
			free (core->theme);
			core->theme = strdup (_arg);
		}
		r_cons_pal_init (core->cons);
		return true;
	}
	bool ret = false;
	char *theme_script = get_theme_script (core, _arg);
	if (R_STR_ISNOTEMPTY (theme_script)) {
		core->cmdfilter = "ec ";
		r_core_cmd_lines (core, theme_script);
		r_cons_pal_reload (core->cons);
		core->cmdfilter = NULL;
		ret = true; // maybe the script fails?
	} else {
		R_LOG_ERROR ("Cannot open '%s' colors theme", _arg);
	}
	free (theme_script);
	return ret;
}

static void list_themes_in_path(RList *list, const char *path) {
	RListIter *iter;
	const char *fn;
	RList *files = r_sys_dir (path);
	r_list_foreach (files, iter, fn) {
		if (*fn && *fn != '.') {
			r_list_append (list, strdup (fn));
		}
	}
	r_list_free (files);
}

R_API char *r_core_get_theme(RCore *core) {
	return core->theme;
}

R_API RList *r_core_list_themes(RCore *core) {
	RList *list = r_list_newf (free);
	core->get_next = false;
	char *tmp = strdup ("default");
	r_list_append (list, tmp);
	char *path = r_xdg_datadir ("cons");
	if (path) {
		list_themes_in_path (list, path);
		R_FREE (path);
	}

	path = r_str_r2_prefix (R2_THEMES R_SYS_DIR);
	if (path) {
		list_themes_in_path (list, path);
		R_FREE (path);
	}

	r_list_sort (list, (RListComparator)strcmp);
	return list;
}

static void nextpal(RCore *core, int mode) {
	// TODO: use r_core_list_themes() here instead of rewalking all the time
	RList *files = NULL;
	RListIter *iter;
	const char *fn;
	char *path = NULL;
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			return;
		}
		pj_a (pj);
	}
	char *home = r_xdg_datadir ("cons");

	core->get_next = false;
	// spaguetti!
	if (home) {
		files = r_sys_dir (home);
		if (files) {
			r_list_sort (files, (RListComparator)strcmp);
			r_list_foreach (files, iter, fn) {
				if (*fn && *fn != '.') {
					if (mode == 'p') {
						const char *nfn = iter->n? iter->n->data: NULL;
						if (!core->theme) {
							free (home);
							r_list_free (files);
							return;
						}
						if (nfn && !strcmp (nfn, core->theme)) {
							r_list_free (files);
							files = NULL;
							free (core->theme);
							core->theme = strdup (fn);
							R_FREE (home);
							goto done;
						}
					} else {
						if (!nextpal_item (core, pj, mode, fn)) {
							r_list_free (files);
							files = NULL;
							R_FREE (home);
							goto done;
						}
					}
				}
			}
		}
		r_list_free (files);
		files = NULL;
		R_FREE (home);
	}

	path = r_str_r2_prefix (R2_THEMES R_SYS_DIR);
	if (path) {
		files = r_sys_dir (path);
		if (files) {
			r_list_sort (files, (RListComparator)strcmp);
			r_list_foreach (files, iter, fn) {
				if (*fn && *fn != '.') {
					if (mode == 'p') {
						const char *nfn = iter->n? iter->n->data: NULL;
						if (!core->theme) {
							free (home);
							r_list_free (files);
							return;
						}
						if (nfn && !strcmp (nfn, core->theme)) {
							free (core->theme);
							core->theme = strdup (fn);
							goto done;
						}
					} else { // next
						if (!nextpal_item (core, pj, mode, fn)) {
							goto done;
						}
					}
				}
			}
		}
	}

done:
	free (path);
	if (core->get_next) {
		R_FREE (core->theme);
		nextpal (core, mode);
		r_list_free (files);
		return;
	}
	if (mode == 'l' && !core->theme && !r_list_empty (files)) {
		//nextpal (core, mode);
	} else if (mode == 'n' || mode == 'p') {
		if (R_STR_ISNOTEMPTY (core->theme)) {
			r_core_cmd_callf (core, "eco %s", core->theme);
		}
	}
	r_list_free (files);
	files = NULL;
	if (mode == 'j') {
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
	}
}

R_API void r_core_echo(RCore *core, const char *input) {
	if (r_str_startswith (input, "64 ")) {
		char *buf = strdup (input);
		r_base64_decode ((ut8*)buf, input + 3, -1);
		if (*buf) {
			r_cons_echo (core->cons, buf);
		}
		free (buf);
	} else {
		char *p = strchr (input, ' ');
		if (p) {
			r_cons_print (core->cons, p + 1);
			r_cons_newline (core->cons);
		}
	}
}

static bool is_static_theme(const char *th) {
	const RConsTheme *theme = r_cons_themes ();
	while (theme && theme->name) {
		const char *tn = theme->name;
		if (!strcmp (th, tn)) {
			return true;
		}
		theme++;
	}
	return false;
}

static bool cmd_ec(RCore *core, const char *input) {
	switch (input[1]) {
	case 'd': // "ecd"
		r_cons_pal_init (core->cons);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_ec);
		break;
	case 'o': // "eco"
		switch (input[2]) {
		case 'j': // "ecoj"
			if (input[3]) {
				r_core_return_invalid_command (core, "ecoj", input[3]);
			} else {
				nextpal (core, 'j');
			}
			break;
		case '*': // "eco*"
			{
				const char *theme_name = core->theme;
				if (input[3]) {
					theme_name = r_str_trim_head_ro (input + 3);
				}
				char *theme_script = get_theme_script (core, theme_name);
				if (R_STR_ISNOTEMPTY (theme_script)) {
					r_cons_printf (core->cons, "%s\n", theme_script);
				} else {
					R_LOG_ERROR ("Cannot find theme '%s'", theme_name);
				}
				free (theme_script);
			}
			break;
		case '!':
			free (r_core_editor (core, core->themepath, NULL));
			cmd_load_theme (core, core->theme); // reload
			break;
		case ' ':
			cmd_load_theme (core, r_str_trim_head_ro (input + 3));
			break;
		case 'o':
			cmd_load_theme (core, core->theme);
			break;
		case 'c':
		case '.':
			r_cons_printf (core->cons, "%s\n", core->theme);
			break;
		case '?':
			r_core_cmd_help (core, help_msg_eco);
			break;
		default:
			{
			RList *themes_list = r_core_list_themes (core);
			RListIter *th_iter;
			const char *th;
			const RConsTheme *themes = r_cons_themes ();
			const RConsTheme *theme = themes;
			while (theme && theme->name) {
				const char *th = theme->name;
				if (input[2] == 'q') {
					r_cons_printf (core->cons, "%s\n", th);
				} else if (core->theme && !strcmp (core->theme, th)) {
					r_cons_printf (core->cons, "- %s\n", th);
				} else {
					r_cons_printf (core->cons, "  %s\n", th);
				}
				theme++;
			}
			r_list_foreach (themes_list, th_iter, th) {
				if (is_static_theme (th)) {
					continue;
				}
				if (input[2] == 'q') {
					r_cons_printf (core->cons, "%s\n", th);
				} else if (core->theme && !strcmp (core->theme, th)) {
					r_cons_printf (core->cons, "- %s\n", th);
				} else {
					r_cons_printf (core->cons, "  %s\n", th);
				}
			}
			r_list_free (themes_list);
			}
			break;
		}
		break;
	case 's': // "ecs"
		r_cons_pal_show (core->cons);
		break;
	case '*': // "ec*"
		r_cons_pal_list (core->cons, 1, NULL);
		break;
	case 'h': // echo
		if (input[2] == 'o') {
			r_core_echo (core, input + 3);
		} else {
			r_cons_pal_list (core->cons, 'h', NULL);
		}
		break;
	case 'j': // "ecj"
		r_cons_pal_list (core->cons, 'j', NULL);
		break;
	case 'c': // "ecc"
		if (input[2]) {
			r_cons_pal_list (core->cons, 'c', input + 2);
		} else {
			r_cons_pal_list (core->cons, 'c', r_config_get (core->config, "scr.css.prefix"));
		}
		break;
	case '\0': // "ec"
		r_cons_pal_list (core->cons, 0, NULL);
		break;
	case 'r': // "ecr"
		r_cons_pal_random (core->cons);
		break;
	case 'n': // "ecn"
		nextpal (core, 'n');
		break;
	case 'p': // "ecp"
		nextpal (core, 'p');
		break;
	case 'H': { // "ecH"
			  char *color_code = NULL;
			  char *word = NULL;
			  int argc = 0;
			  int delta = (input[2])? 3: 2;
			  char** argv = r_str_argv (r_str_trim_head_ro (input + delta), &argc);
			  switch (input[2]) {
			  case '?':
				  r_core_cmd_help (core, help_msg_ecH);
				  r_str_argv_free (argv);
				  return false;
			  case '-': // ecH-
				  if (input[3] == '*') {
					  r_meta_del (core->anal, R_META_TYPE_HIGHLIGHT, 0, UT64_MAX);
				  } else {
					  r_meta_del (core->anal, R_META_TYPE_HIGHLIGHT, core->addr, 1);
					  // r_meta_set_string (core->anal, R_META_TYPE_HIGHLIGHT, core->addr, "");
				  }
				  r_str_argv_free (argv);
				  return false;
			  case '.':
				  r_meta_print_list_in_function (core->anal, R_META_TYPE_HIGHLIGHT, 0, core->addr, NULL, NULL);
				  r_str_argv_free (argv);
				  return false;
			  case '\0':
				  r_meta_print_list_all (core->anal, R_META_TYPE_HIGHLIGHT, 0, NULL, NULL);
				  r_str_argv_free (argv);
				  return false;
			  case 'j':
				  r_meta_print_list_all (core->anal, R_META_TYPE_HIGHLIGHT, 'j', NULL, NULL);
				  r_str_argv_free (argv);
				  return false;
			  case '*':
				  r_meta_print_list_all (core->anal, R_META_TYPE_HIGHLIGHT, '*', NULL, NULL);
				  r_str_argv_free (argv);
				  return false;
			  case ' ':
			  case 'i': // "ecHi"
				  if (argc) {
					  char *dup = r_str_newf ("bgonly %s", argv[0]);
					  color_code = r_cons_pal_parse (core->cons, dup, NULL);
					  free (dup);
					  if (!color_code) {
						  R_LOG_ERROR ("Unknown color %s", argv[0]);
						  r_str_argv_free (argv);
						  return true;
					  }
				  }
				  break;
			  case 'w': // "ecHw"
				  if (!argc) {
					  r_core_cmd_help_match (core, help_msg_ecH, "ecHw");
					  r_str_argv_free (argv);
					  return true;
				  }
				  word = strdup (argv[0]);
				  if (argc > 1) {
					  char *dup = r_str_newf ("bgonly %s", argv[1]);
					  color_code = r_cons_pal_parse (core->cons, dup, NULL);
					  R_FREE (dup);
					  if (!color_code) {
						  R_LOG_ERROR ("Unknown color %s", argv[1]);
						  r_str_argv_free (argv);
						  free (word);
						  return true;
					  }
				  }
				  break;
			  default:
				  R_LOG_INFO ("See ecH?");
				  r_str_argv_free (argv);
				  return true;
			  }
			  r_meta_set_string (core->anal, R_META_TYPE_HIGHLIGHT, core->addr, "");
			  const char *str = r_meta_get_string (core->anal, R_META_TYPE_HIGHLIGHT, core->addr);
			  char *dup = r_str_newf ("%s \"%s%s\"", r_str_get (str), r_str_get (word),
					  color_code ? color_code : core->cons->context->pal.wordhl);
			  r_meta_set_string (core->anal, R_META_TYPE_HIGHLIGHT, core->addr, dup);
			  r_str_argv_free (argv);
			  free (color_code);
			  R_FREE (word);
			  R_FREE (dup);
		  }
		  break;
	case ' ':
		  {
			 char *p = strdup (input + 2);
			 char *q = strchr (p, '=');
			 if (!q) {
				 q = strchr (p, ' ');
			 }
			 if (q) {
				 // Set color
				 *q++ = 0;
				 if (r_cons_pal_set (core->cons, p, q)) {
					 r_cons_pal_reload (core->cons);
				 }
			 } else {
				 char color[32] = {0};
				 RColor rcolor = r_cons_pal_get (core->cons, p);
				 r_cons_rgb_str (core->cons, color, sizeof (color), &rcolor);
				 if (*color) {
					 eprintf ("(%s)(%sCOLOR"Color_RESET")\n", p, color);
				 } else {
					 R_LOG_ERROR ("Invalid palette color '%s'", p);
				 }
			 }
			 free (p);
		 }
		break;
	default:
		r_core_return_invalid_command (core, "ec", input[1]);
		break;
	}
	return true;
}

static void r2rc_set(RCore *core, const char * R_NULLABLE k, const char * R_NULLABLE v) {
	char *rcfile = r_file_home (".radare2rc");
	char *rcdata = r_file_slurp (rcfile, NULL);
	if (k) {
		char *line;
		RListIter *iter;
		RList *lines = r_str_split_list (rcdata, "\n", 0);
		RStrBuf *sb = r_strbuf_new ("");
		bool found = false;
		char *kk = r_str_newf ("e %s", k);
		r_list_foreach (lines, iter, line) {
			const char *oline = line;
			if (*oline == '\'') {
				oline++;
			}
			if (r_str_startswith (oline, kk)) {
				if (v) {
					if (!found && *v) {
						r_strbuf_appendf (sb, "'e %s=%s\n", k, v);
					}
				} else {
					r_cons_println (core->cons, line);
				}
				found = true;
			} else {
				r_strbuf_appendf (sb, "%s\n", line);
			}
		}
		free (kk);
		if (v) {
			if (!found && *v) {
				r_strbuf_appendf (sb, "'e %s=%s\n", k, v);
			}
			char *out = r_strbuf_drain (sb);
			r_list_free (lines);
			r_str_trim (out);
			r_file_dump (rcfile, (const ut8*)out, -1, false);
			free (out);
		} else {
			r_strbuf_free (sb);
		}
	} else {
		r_cons_println (core->cons, rcdata);
	}
	free (rcdata);
	free (rcfile);
}

static void cmd_eplus(RCore *core, const char *input) {
	char *s = r_str_trim_dup (input);
	char *eq = strchr (s, '=');
	if (*s) {
		if (eq) {
			r_str_trim (s);
			*eq++ = 0;
			r_str_trim (eq);
			const char *k = s;
			const char *v = eq;
			r2rc_set (core, k, v);
		} else {
			r2rc_set (core, s, NULL);
		}
	} else {
		r2rc_set (core, NULL, NULL);
	}
	free (s);
}

static void core_config_list(RCore *core, const char *str, int rad) {
	char *res = r_config_list (core->config, str, rad);
	r_cons_print (core->cons, res);
	free (res);
}

static void core_config_eval(RCore *core, const char *input, bool uhm) {
	char *res = r_config_eval (core->config, input, uhm, NULL);
	r_cons_print (core->cons, res);
	free (res);
}

static int cmd_eval(void *data, const char *input) {
	RCore *core = (RCore *)data;
	RCons *cons = core->cons;
	switch (input[0]) {
	case '\0': // "e"
		core_config_list (core, NULL, 0);
		break;
	case '?': // "e?"
		switch (input[1]) {
		case '\0': r_core_cmd_help (core, help_msg_e); break;
		case '?': core_config_list (core, input + 2, 2); break;
		default: core_config_list (core, input + 1, 3); break;
		}
		break;
	case 't': // "et"
		if (input[1] == 'a') {
			r_cons_printf (cons, "%s\n", (r_num_rand (10) % 2)? "wen": "son");
		} else if (input[1] == ' ' && input[2]) {
			RConfigNode *node = r_config_node_get (core->config, input+2);
			if (node) {
				const char *type = r_config_node_type (node);
				if (type && *type) {
					r_cons_println (cons, type);
				}
			}
		} else {
			r_core_cmd_help_contains (core, help_msg_e, "et");
		}
		break;
	case 'n': // "en" "env"
		if (strchr (input, '?')) {
			r_core_cmd_help_contains (core, help_msg_e, "en");
			break;
		}
		if (!strcmp (input + 1, "vj")) {
			char **e = r_sys_get_environ ();
			PJ *pj = r_core_pj_new (core);
			pj_o (pj);
			if (e != NULL) {
				while (*e) {
					char *s = strdup (*e);
					char *q = strchr (s, '=');
					if (q) {
						*q = 0;
						pj_ks (pj, s, q + 1);
					}
					free (s);
					e++;
				}
			}
			pj_end (pj);
			char *s = pj_drain (pj);
			r_cons_println (cons, s);
			free (s);
		} else if (!strcmp (input + 1, "v*")) {
			char **e = r_sys_get_environ ();
			if (e != NULL) {
				while (*e) {
					r_cons_printf (cons, "%%%s\n", *e);
					e++;
				}
			}
		} else if (!strchr (input, '=')) {
			const char *var = strchr (input, ' ');
			if (var) {
				var = r_str_trim_head_ro (var);
			}
			char *p = r_sys_getenv (var);
			if (p) {
				r_cons_println (cons, p);
				free (p);
			} else if (!var || !*var) {
				char **e = r_sys_get_environ ();
				if (e != NULL) {
					while (*e) {
						r_cons_println (cons, *e);
						e++;
					}
				}
			}
		} else if (strlen (input) > 3) {
			char *v, *k = strdup (input + 3);
			if (!k) {
				break;
			}
			v = strchr (k, '=');
			if (*k && v) {
				*v++ = 0;
				r_str_trim (k);
				r_str_trim (v);
				char *last = k + strlen (k) - 1;
				if (*k && *last == '%') {
					*last = 0;
					r_str_trim (k);
				}
				r_sys_setenv (k, v);
			}
			free (k);
		}
		return true;
	case 'x': // "ex"
		// XXX we need headers for the cmd_xxx files.
		return cmd_quit (data, "");
	case 'J': // "eJ"
		core_config_list (core, NULL, 'J');
		break;
	case 'j': // "ej"
		core_config_list (core, NULL, 'j');
		break;
	case 'v': // verbose
		core_config_list (core, r_str_trim_head_ro (input + 1), 'v');
		break;
	case 'q': // quiet list of eval keys
		core_config_list (core, NULL, 'q');
		break;
	case 'c': // "ec"
		return cmd_ec (core, input);
	case 'd': // "ed"
		if (input[1] == '?') {
			r_core_cmd_help_contains (core, help_msg_e, "ed");
		} else if (input[1] == '*') {
			char *file = r_file_home (".radare2rc");
			char *data = r_file_slurp (file, NULL);
			r_cons_println (cons, data);
			free (data);
			free (file);
		} else if (input[1] == '+') {
			cmd_eplus (core, input + 2);
		} else if (input[1] == '-') { // "ed-"
			const bool prompt = (input[2] != '!');
			char *file = r_file_home (".radare2rc");
			if (file) {
				const bool rmfile = !prompt || r_cons_yesno (cons, 'n', "Do you want to delete ~/.radare2? (Y/n)");
				if (rmfile) {
					r_file_rm (file);
				}
				free (file);
			}
		} else {
			char *file = r_file_home (".radare2rc");
			if (r_cons_is_interactive (cons)) {
				r_file_touch (file);
				char *res = r_cons_editor (cons, file, NULL);
				if (res) {
					if (r_cons_yesno (cons, 'y', "Reload? (Y/n)")) {
						r_core_run_script (core, file);
					}
				}
			} else {
				r_core_run_script (core, file);
			}
			free (file);
		}
		break;
	case '+': // "e+"
		cmd_eplus (core, input + 1);
		break;
	case 'e': // "ee"
		if (input[1] == ' ') {
			char *p;
			const char *input2 = strchr (input + 2, ' ');
			input2 = (input2) ? input2 + 1 : input + 2;
			const char *val = r_config_get (core->config, input2);
			p = r_core_editor (core, NULL, val);
			if (p) {
				r_str_replace_char (p, '\n', ';');
				r_config_set (core->config, input2, p);
			}
		} else {
			r_core_cmd_help_contains (core, help_msg_e, "ee");
		}
		break;
	case '!': // "e!"
		input = r_str_trim_head_ro (input + 1);
		if (R_STR_ISNOTEMPTY (input) && *input != '?') {
			if (!r_config_toggle (core->config, input)) {
				R_LOG_ERROR ("'%s' is not a boolean variable", input);
			}
		} else {
			r_core_cmd_help_match (core, help_msg_e, "e!");
		}
		break;
	case 's': // "es"
		core_config_list (core, (input[1])? input + 1: NULL, 's');
		break;
	case '-': // "e-"
		r_core_config_init (core);
		//eprintf ("BUG: 'e-' command locks the eval hashtable. patches are welcome :)\n");
		break;
	case '*': // "e*"
		core_config_list (core, NULL, 1);
		break;
	case 'r': // "er"
		if (input[1]) {
			const char *key = input + ((input[1] == ' ')? 2: 1);
			if (!r_config_readonly (core->config, key)) {
				R_LOG_ERROR ("cannot find key '%s'", key);
			}
		} else {
			r_core_cmd_help_contains (core, help_msg_e, "er");
		}
		break;
	case ':': // "e:"
		core_config_eval (core, input + 1, true);
		break;
	case ',': // "e,"
		cmd_eval_table (core, input + 1);
		break;
	case '.': // "e "
	case ' ': // "e "
		if (strchr (input, '=')) {
			core_config_eval (core, r_str_trim_head_ro (input + 1), false);
		} else {
			if (r_str_endswith (input, ".") && !r_str_endswith (input, "..")) {
				core_config_list (core, input + 1, 0);
			} else if (r_str_endswith (input, ".?")) {
				char *w = r_str_ndup (input, strlen (input) - 1);
				core_config_list (core, w, 2);
				free (w);
			} else {
				// XXX we cant do "e cmd.gprompt=dr=", because the '=' is a token, and quotes dont affect him
				core_config_eval (core, r_str_trim_head_ro (input + 1), false);
			}
		}
		break;
	default:
		r_core_return_invalid_command (core, "e", *input);
		break;
	}
	return 0;
}
#endif
