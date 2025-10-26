/* radare - LGPL - Copyright 2009-2024 - pancake */

#if R_INCLUDE_BEGIN

// R2R db/cmd/projects

static RCoreHelpMessage help_msg_P = {
	"用法:", "P[?.+-*cdilnsS] [file]", "项目管理",
	"P", " [file]", "打开项目 (原为 Po)",
	"P.", "", "显示当前加载的项目 (参见 prj.name)",
	"P+", " [name]", "保存项目 (与 Ps 相同，但不检查更改)",
	"P-", " [name]", "删除项目",
	"P*", "", "以 r2 命令打印项目脚本",
	"P!", "([cmd])", "在项目目录中打开 shell 或运行命令",
	"Pc", "", "关闭当前项目",
	"Pd", " [N]", "比较第 N 次提交",
	"Pi", " [file]", "显示项目信息",
	"Pl", "", "列出所有项目",
	"Pn", " -", "使用 cfg.editor 编辑当前加载项目的注释",
	"Pn", "[j]", "管理与项目关联的注释",
	"Ps", " [file]", "保存项目 (参见 dir.projects)",
	"PS", " [file]", "保存脚本文件",
	"PS*", " [name]", "打印项目脚本文件 (类似 P*，但需要项目)",
	"Pz", "[ie] [zipfile]", "以 zip 格式导入/导出 r2 项目 (.zrp 扩展名)",
	"注意:", "", "'e prj.name' 变量可以保存/打开/重命名/列出项目",
	"注意:", "", "参见其他 'e??prj.' 变量获取更多选项",
	"注意:", "", "项目存储在 dir.projects 中",
	NULL
};

static RCoreHelpMessage help_msg_Pn = {
	"用法:", "Pn[j-?] [...]", "项目注释",
	"Pn", "", "显示项目注释",
	"Pn", " -", "使用 cfg.editor 编辑注释",
	"Pn", " [base64]", "设置注释文本",
	"Pn-", "", "删除注释",
	"Pn-", "str", "删除注释中匹配 /str/ 的行",
	"Pn+", "str", "向注释追加一行",
	"Pnj", "", "以 base64 显示注释",
	"Pnj", " [base64]", "以 base64 设置注释",
	"Pnx", "", "运行项目注释命令",
	NULL
};

static RCoreHelpMessage help_msg_Pz = {
	"用法:", "Pz[ie] ([file])", "以 Zip 格式导入/导出项目",
	"Pz", "", "导出项目到 prjname.zrp",
	"Pze", " foo.zrp", "导出项目，与 Pz 相同",
	"Pzi", " foo.zrp", "从给定的 zrp 文件导入 radare2 项目",
	NULL
};

static bool r_core_project_zip_import(RCore *core, const char *inzip) {
	if (inzip && !r_str_endswith (inzip, ".zrp")) {
		R_LOG_ERROR ("Project zips must use the .zrp extension");
		return false;
	}
	char *prjdir = r_file_abspath (r_config_get (core->config, "dir.projects"));
	int ret = r_sys_mkdirp (prjdir);
	if (!ret) {
		R_LOG_ERROR ("Cannot mkdir dir.projects");
	}
	// unzip in there
	int res = r_sys_cmdf ("unzip %s -d %s", inzip, prjdir);
	free (prjdir);
	return res == 0;
}

// export project
static void r_core_project_zip_export(RCore *core, const char *prjname, const char *outzip) {
	char *prj_dir = r_file_abspath (r_config_get (core->config, "dir.projects"));
	char *cwd = r_sys_getdir ();
	const char *prj_name = prjname? prjname: r_config_get (core->config, "prj.name");
	if (R_STR_ISEMPTY (prj_name)) {
		R_LOG_ERROR ("No project to export");
		return;
	}
	if (outzip && !r_str_endswith (outzip, ".zrp")) {
		R_LOG_ERROR ("Project zips must use the .zrp extension");
		return;
	}
	if (r_sys_chdir (prj_dir)) {
		if (!strchr (prj_name, '\'')) {
			char *zipfile = r_str_newf ("%s/%s.zrp", cwd, prj_name);
			r_file_rm (zipfile);
			// XXX use the ZIP api instead!
			const char *ofn = outzip? outzip: zipfile;
			char *out = (*ofn == '/')? strdup (ofn): r_str_newf ("%s/%s", cwd, ofn);
			r_sys_cmdf ("zip -r %s %s", out, prj_name);
			free (out);
			free (zipfile);
		} else {
			R_LOG_WARN ("Command injection attempt?");
		}
	} else {
		R_LOG_ERROR ("Cannot chdir %s", prj_dir);
	}
	r_sys_chdir (cwd);
	free (cwd);
}

static void cmd_Pz(RCore *core, const char *cmd) {
	char *arg = strchr (cmd, ' ');
	if (arg) {
		arg++;
	}
	switch (*cmd) {
	case 'i': // "Pzi"
		r_core_project_zip_import (core, arg);
		break;
	case 'e': // "Pze"
	case ' ':
		r_core_project_zip_export (core, NULL, arg);
		break;
	default:
		r_core_cmd_help (core, help_msg_Pz);
		break;
	}
}

static int cmd_project(void *data, const char *input) {
	RCore *core = (RCore *) data;
	const char *file;
	const char *fileproject = r_config_get (core->config, "prj.name");

	if (!input) {
		return false;
	}
	char *str = strdup (fileproject);
	const char *arg = strchr (input, ' ');
	if (arg) {
		arg++;
	} else {
		if (*input) {
			arg = input + 1;
			if (*arg == '&') {
				arg++;
			}
		}
	}
	file = arg;
	switch (input[0]) {
	case 'c': // "Pc"
		if (R_STR_ISNOTEMPTY (r_config_get (core->config, "prj.name"))) {
			r_project_close (core->prj);
			r_config_set (core->config, "prj.name", "");
		} else {
			R_LOG_WARN ("No project to close");
		}
		break;
	case 'o': // "Po" DEPRECATED
		R_LOG_WARN ("Po is deprecated, use 'P [prjname]' instead");
		// fallthru
	case ' ': // "P [prj]"
		if (input[1] == '&') { // "Po&"
			r_core_cmdf (core, "& Po %s", file);
		} else if (input[1]) { // "Po"
			bool success = r_core_project_open (core, file);
			r_core_return_code (core, success? 0: 1);
		} else {
			if (R_STR_ISNOTEMPTY (str)) {
				r_cons_println (core->cons, str);
			}
		}
		break;
	case 'd': // "Pd"
		{
			char *pdir = r_file_new (
				r_config_get (core->config, "dir.projects"),
				r_config_get (core->config, "prj.name"), NULL);
			if (r_syscmd_pushd (pdir)) {
				if (r_file_is_directory (".git")) {
					// TODO: Use ravc2 api
					r_sys_cmdf ("git diff @~%d", atoi (input + 1));
				} else {
					R_LOG_TODO ("Not a git project. Diffing projects is WIP for now");
				}
				r_syscmd_popd ();
			}
			free (pdir);
		}
		break;
	case '-': // "P-"
		if (!strcmp (input + 1, "-")) {
			//r_project_close (core->prj);
			r_config_set (core->config, "prj.name", "");
		} else if (input[1]) {
			if (R_STR_ISNOTEMPTY (file)) {
				r_core_project_delete (core, file);
			} else {
			//	r_project_close (core->prj);
				r_config_set (core->config, "prj.name", "");
			}
		} else {
			// r_project_close (core->prj);
			r_config_set (core->config, "prj.name", "");
		}
		break;
	case 'z': // "Pz"
		cmd_Pz (core, r_str_trim_head_ro (input + 1));
		break;
	case '+': // "P+"
		// xxx
	case 's': // "Ps"
		if (R_STR_ISEMPTY (file)) {
			file = str;
		}
		if (!R_STR_ISEMPTY (file)) {
			bool res = r_core_project_save (core, file);
			if (res) {
				r_core_return_code (core, 0);
			} else {
				R_LOG_ERROR ("Cannot save project");
				r_core_return_code (core, 1);
			}
		} else {
			r_core_return_code (core, 1);
			R_LOG_INFO ("Use: Ps [projectname]");
		}
		break;
	case '!': // "P!"
		if (input [1] == '?') {
			r_core_cmd_help_contains (core, help_msg_P, "P!");
		} else if (r_config_get_b (core->config, "scr.interactive")) {
			char *pdir = r_file_new (
				r_config_get (core->config, "dir.projects"),
				r_config_get (core->config, "prj.name"), NULL);
			r_syscmd_pushd (pdir);
			free (pdir);
			const char *cmd = r_str_trim_head_ro (input + 1);
			if (R_STR_ISNOTEMPTY (cmd)) {
				r_sys_cmdf ("%s", cmd);
			} else {
#if R2__WINDOWS__
				r_sys_cmdf ("cmd");
#else
				r_sys_cmdf ("sh");
#endif
			}
			r_syscmd_popd ();
		} else {
			R_LOG_ERROR ("P! requires scr.interactive to open a shell");
		}
		break;
	case '*': // "P*"
		// XXX dont use /dev/stdout
#if R2__WINDOWS__
		r_core_project_save_script (core, "CON", R_CORE_PRJ_ALL);
#else
		r_core_project_save_script (core, "/dev/stdout", R_CORE_PRJ_ALL);
#endif
		break;
	case 'S': // "PS"
		if (input[1] == ' ') {
			r_core_project_save_script (core, r_str_trim_head_ro (input + 2), R_CORE_PRJ_ALL);
		} else if (input[1] == '*') { // "PS*"
			if (input[2]) {
				r_core_project_cat (core, r_str_trim_head_ro (input + 2));
			} else {
				if (R_STR_ISEMPTY (fileproject)) {
					R_LOG_ERROR ("No project set. Use 'P*' or 'Ps <prjname>'");
				} else {
					r_core_project_cat (core, fileproject);
				}
			}
		} else {
			r_core_cmd_help_contains (core, help_msg_P, "PS");
		}
		break;
	case 'n': // "Pn"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_Pn);
		} else if (R_STR_ISEMPTY (fileproject)) {
			R_LOG_ERROR ("No project");
		} else {
			switch (input[1]) {
			case '-': // "Pn-"
				/* remove lines containing specific words */
			{
				FILE *fd = r_sandbox_fopen (str, "w");
				if (!fd) {
					R_LOG_ERROR ("Cannot open %s", str);
				} else {
					char *str = r_core_project_notes_file (core, fileproject);
					char *data = r_file_slurp (str, NULL);
					int count = 0;
					if (data) {
						char *ptr, *nl;
						for (ptr = data; ptr; ptr = nl) {
							nl = strchr (ptr, '\n');
							if (nl) {
								*nl++ = 0;
								if (strstr (ptr, input + 2)) {
									count++;
								} else {
									fprintf (fd, "%s\n", ptr);
								}
							}
						}
						free (data);
					}
					if (count > 0) {
						R_LOG_ERROR ("Deleted %d lines", count);
					}
					free (str);
					fclose (fd);
				}
			}
			break;
			case ' ': // "Pn "
				if (input[2] == '-') {
					char *str = r_core_project_notes_file (core, fileproject);
					// edit with cfg.editor
					const char *editor = r_config_get (core->config, "cfg.editor");
					if (str && *str && editor && *editor) {
						r_sys_cmdf ("%s %s", editor, str);
					} else {
						R_LOG_ERROR ("No cfg.editor configured");
					}
					free (str);
				} else {
					// char *str = r_core_project_notes_file (core, fileproject);
					// append line to project notes
					char *str = r_core_project_notes_file (core, fileproject);
					char *data = r_file_slurp (str, NULL);
					FILE *fd = r_sandbox_fopen (str, "a");
					if (fd) {
						fprintf (fd, "%s\n", input + 2);
						fclose (fd);
					}
					free (str);
					free (data);
				}
				break;
			case '+': // "Pn+"
				{
					char *str = r_core_project_notes_file (core, fileproject);
					char *data = r_file_slurp (str, NULL);
					data = r_str_append (data, input + 2);
					data = r_str_append (data, "\n");
					r_file_dump (str, (const ut8*)data, strlen (data), false);
					free (data);
					free (str);
				}
				break;
			case 'j': // "Pnj"
				if (!input[2]) {
					size_t len = 0;
					/* get base64 string */
					char *str = r_core_project_notes_file (core, fileproject);
					if (str) {
						char *data = r_file_slurp (str, &len);
						char *res = r_base64_encode_dyn ((const ut8*)data, (int)len);
						if (res) {
							r_cons_println (core->cons, res);
							free (res);
						}
						free (data);
						free (str);
					}
				} else if (input[2] == ' ') {
					/* set base64 string */
					ut8 *data = r_base64_decode_dyn (input + 3, -1, NULL);
					if (data) {
						char *str = r_core_project_notes_file (core, fileproject);
						if (str) {
							r_file_dump (str, data, strlen ((const char *) data), 0);
							free (str);
						}
						free (data);
					}
				} else {
					r_core_cmd_help_contains (core, help_msg_P, "Pn");
				}
				break;
			case 'x': // "Pnx"
				r_core_project_execute_cmds (core, fileproject);
				break;
			case 0: // "Pn"
			{
				char *str = r_core_project_notes_file (core, fileproject);
				char *data = r_file_slurp (str, NULL);
				if (data) {
					r_cons_println (core->cons, data);
					free (data);
				}
				free (str);
			}
			break;
			}
		}
		break;
	case 'i': // "Pi" DEPRECATE
		if (R_STR_ISNOTEMPTY (file)) {
			char *prj_name = r_core_project_name (core, file);
			if (!R_STR_ISEMPTY (prj_name)) {
				r_cons_println (core->cons, prj_name);
				free (prj_name);
			}
		} else if (r_project_is_loaded (core->prj)) {
			if (R_STR_ISNOTEMPTY (core->prj->name)) {
				r_cons_println (core->cons, core->prj->name);
			}
			if (R_STR_ISNOTEMPTY (core->prj->path)) {
				r_cons_println (core->cons, core->prj->path);
			}
		}
		break;
	case '.': // "P."
		r_cons_printf (core->cons, "%s\n", fileproject);
		break;
	case 'l':
		r_core_project_list (core, input[1]);
		break;
	case 0: // "P"
	case 'P':
	case 'j': // "Pj"
		r_core_project_list (core, input[0]);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_P);
		break;
	default:
		r_core_return_invalid_command (core, "P", *input);
		break;
	}
	free (str);
	return 0;
}

#endif
