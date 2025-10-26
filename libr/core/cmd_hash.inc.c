/* radare - LGPL - Copyright 2009-2024 - pancake, nibble */

#if R_INCLUDE_BEGIN

static RCoreHelpMessage help_msg_hash = {
	"用法:", "#!<解释器>", "[<参数>] [<文件] [<<eof]",
	"#", "", "注释 - 不执行任何操作",
	"#!", "", "列出所有可用的解释器",
	"#!!", "", "重置 rlang 会话上下文 (见 js!)",
	"#!?", "", "显示此帮助信息",
	"#!?j", "", "以 JSON 格式列出所有可用的解释器",
	"#!?q", "", "列出所有可用的语言插件名称 (见 Ll?)",
	"#!<lang>?", "", "显示 <lang> 的帮助 (v, python, mujs, ..)",
	"#!<lang>", " [文件]", "使用语言插件解释给定文件",
	"#!<lang>", " -e [表达式|base64:..]", "使用语言插件运行给定表达式",
	"#!<lang>", "", "进入给定语言插件的交互提示符",
	"#!pipe", " node -e 'console.log(123)''", "在 r2pipe 环境中运行带参数的程序",
	NULL
};

static int cmd_hash_bang(RCore *core, const char *input) {
	if (r_sandbox_enable (0)) {
		R_LOG_ERROR ("hashbang disabled in sandbox mode");
		return false;
	}
	if (!strchr (input, ' ') && r_str_endswith (input, "?")) {
		char *ex = strchr (input, '!');
		if (ex) {
			char *name = r_str_ndup (ex + 1, strlen (ex) - 2);
			RLangPlugin *lp = r_lang_get_by_name (core->lang, name);
			if (lp) {
				if (lp->example) {
					r_cons_println (core->cons, lp->example);
				} else {
					R_LOG_ERROR ("%s plugin does not provide an example", name);
				}
			} else {
				if (*name) {
					R_LOG_ERROR ("Unknown rlang plugin '%s'", name);
				} else {
					r_core_cmd_help_contains (core, help_msg_hash, "#!");
				}
			}
			free (name);
		}
		return false;
	}
	int ac;
	char **av = r_str_argv (input + 1, &ac);
	if (ac > 0) {
		RLangPlugin *p = r_lang_get_by_name (core->lang, av[0]);
		if (p) {
			// I see no point in using r_lang_use here, as we already haz a ptr to the pluging in our handz
			// Maybe add r_lang_use_plugin in r_lang api?
			if (!r_lang_use_plugin (core->lang, p)) {
				R_LOG_ERROR ("Sorry but I don't know this this language");
				return false;
			}
			if (ac > 1) {
				if (!strcmp (av[1], "-e")) {
					const char *run_str = r_str_trim_head_ro (strstr (input + 2, "-e") + 2);
					if (run_str) {
						if (r_str_startswith (run_str, "base64:")) {
							int len = 0;
							char *o = (char *)sdb_decode (run_str + 7, &len);
							if (o) {
								r_lang_run_string (core->lang, o);
							} else {
								R_LOG_ERROR ("Invalid base64");
								return 0;
							}
						} else {
							r_lang_run_string (core->lang, run_str);
						}
					} else {
						R_LOG_ERROR ("Invalid file name");
					}
				} else {
					if (r_lang_set_argv (core->lang, ac - 1, &av[1])) {
						r_lang_run_file (core->lang, av[1]);
					} else {
						char *run_str = strstr (input + 2, av[1]);
						if (run_str) {
							r_lang_run_file (core->lang, run_str);
						} else {
							R_LOG_ERROR ("Invalid file name");
						}
					}
				}
			} else {
				if (r_cons_is_interactive (core->cons)) {
					r_lang_prompt (core->lang);
				} else {
					R_LOG_ERROR ("scr.interactive required to run the rlang prompt");
				}
			}
		} else if (av[0][0] == '?') {
			const char mod = av[0][1];
			switch (mod) {
			case 'j':
			case 'q':
				r_core_list_lang (core, mod);
				break;
			case '*':
				r_core_list_lang (core, 0);
				break;
			case '?':
				R_LOG_INFO ("Missing halp");
				break;
			default:
				r_core_return_invalid_command (core, "#!", av[0][0]);
				break;
			}
		}
	} else {
		r_core_list_lang (core, 0);
	}
	r_str_argv_free (av);
	return true;
}

static int cmd_hash(void *data, const char *input) {
	RCore *core = (RCore *)data;

	if (*input == '!') {
		if (input[1] == '!') {
			r_lang_setup (core->lang);
			return 0;
		}
		return cmd_hash_bang (core, input);
	}
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_hash);
		return false;
	}
	/* this is a comment - captain obvious
	   should not be reached, see r_core_cmd_subst() */
	return 0;
}

#endif // R_INCLUDE_BEGIN
