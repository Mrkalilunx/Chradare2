static RCoreHelpMessage help_msg_y = {
	"用法:", "y[fptxy] [len] [[@]addr]", " # 查看 wd? 以获取 memcpy，和 'yf' 相同。",
	"y!", "", "打开 cfg.editor 以编辑剪贴板",
	"y", " 16 0x200", "从 0x200 复制 16 字节到剪贴板",
	"y", " 16 @ 0x200", "从 0x200 复制 16 字节到剪贴板",
	"y", " 16", "复制 16 字节到剪贴板",
	"y", "", "显示 yank 缓冲区信息（原始 len 字节）",
	"y*", "", "在 r2 命令中打印已 yank 的内容",
	"y-", "", "清空 / 重置剪贴板",
	"y8", "", "以十六进制对的形式打印剪贴板内容",
	"yf", " [L] [O] [file]", "从 [file] 的偏移 [O] 复制 [L] 字节到剪贴板",
	"yfa", " [filepath]", "从文件复制所有字节到剪贴板",
	"yfx", " 10203040", "从十六进制对中 yank（和 ywx 相同）",
	"yj", "", "以 JSON 命令打印已 yank 的内容",
	"yp", "", "打印剪贴板内容",
	"ys", "", "以字符串形式打印剪贴板内容",
	"yt", " 64 0x200", "从当前寻址位置复制 64 字节到 0x200",
	"ytf", " file", "将剪贴板转储到给定文件",
	"yw", " hello world", "从字符串 yank",
	"ywx", " 10203040", "从十六进制对中 yank（和 yfx 相同）",
	"yx", "", "以十六进制打印剪贴板内容",
	"yy", " 0x3344", "将剪贴板内容粘贴到 0x3344",
	"yy", " @ 0x3344", "将剪贴板内容粘贴到 0x3344",
	"yy", "", "在当前寻址位置粘贴剪贴板内容",
	"yz", " [len]", "复制以 nul 结尾的字符串（最多到块大小）到剪贴板",
	NULL
};

static int cmd_yank(void *data, const char *input) {
	ut64 n;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case ' ': // "y "
		{
			char *args = r_str_trim_dup (input + 1);
			char *arg = r_str_after (args, ' ');
			ut64 addr = arg? r_num_math (core->num, arg): core->addr;
			r_core_yank (core, addr, r_num_math (core->num, args));
			free (args);
		}
		break;
	case '-': // "y-"
		r_core_yank_unset (core);
		break;
	case 'l': // "yl"
		r_core_return_value (core, r_buf_size (core->yank_buf));
		break;
	case 'r': // "yr"
		R_LOG_ERROR ("Missing plugin. Run: r2pm -ci r2yara");
		r_core_return_code (core, 1);
		break;
	case 'y': // "yy"
		input = r_str_trim_head_ro (input);
		n = input[1]? r_num_math (core->num, input + 1): core->addr;
		r_core_yank_paste (core, n, 0);
		break;
	case 'x': // "yx"
		r_core_yank_hexdump (core, r_num_math (core->num, input + 1));
		break;
	case 'z': // "yz"
		r_core_yank_string (core, core->addr, r_num_math (core->num, input + 1));
		break;
	case 'w': // "yw" ... we have yf which makes more sense than 'w'
		switch (input[1]) {
		case ' ':
			r_core_yank_set (core, 0, (const ut8*)input + 2, strlen (input + 2));
			break;
		case 'x':
			if (input[2] == ' ') {
				char *out = strdup (input + 3);
				int len = r_hex_str2bin (input + 3, (ut8*)out);
				if (len > 0) {
					r_core_yank_set (core, core->addr, (const ut8*)out, len);
				} else {
					R_LOG_ERROR ("Invalid length");
				}
				free (out);
			} else {
				r_core_cmd_help_match (core, help_msg_y, "ywx");
			}
			// r_core_yank_write_hex (core, input + 2);
			break;
		default:
			r_core_cmd_help_match (core, help_msg_y, "ywx");
			break;
		}
		break;
	case 'p': // "yp"
		r_core_yank_cat (core, r_num_math (core->num, input + 1));
		break;
	case 's': // "ys"
		r_core_yank_cat_string (core, r_num_math (core->num, input + 1));
		break;
	case 't': // "yt"
		switch (input[1]) {
		case 'f': // "ytf"
			{
			ut64 tmpsz;
			const char *file = r_str_trim_head_ro (input + 2);
			const ut8 *tmp = r_buf_data (core->yank_buf, &tmpsz);
			if (!tmpsz) {
				R_LOG_ERROR ("No buffer has been yanked");
				break;
			}

			if (*file == '$') {
				r_cmd_alias_set_raw (core->rcmd, file+1, tmp, tmpsz);
			} else if (*file == '?' || !*file) {
				r_core_cmd_help_match (core, help_msg_y, "ytf");
			} else {
				if (!r_file_dump (file, tmp, tmpsz, false)) {
					R_LOG_ERROR ("Cannot dump to '%s'", file);
				}
			}
			}
			break;
		case ' ':
			r_core_yank_to (core, input + 1);
			break;
		case '?':
			r_core_cmd_help_contains (core, help_msg_y, "yt");
			break;
		default:
			r_core_return_invalid_command (core, "yt", input[1]);
			break;
		}
		break;
	case 'f': // "yf"
		switch (input[1]) {
		case ' ': // "yf" // "yf [filename] [nbytes] [offset]"
			r_core_yank_file_ex (core, input + 1);
			break;
		case 'x': // "yfx"
			r_core_yank_hexpair (core, input + 2);
			break;
		case 'a': // "yfa"
			r_core_yank_file_all (core, input + 2);
			break;
		case '?':
			r_core_cmd_help_contains (core, help_msg_y, "yf");
			break;
		default:
			r_core_return_invalid_command (core, "yf", input[1]);
			break;
		}
		break;
	case '!': // "y!"
		{
			char *sig = r_core_cmd_str (core, "y*");
			if (R_STR_ISEMPTY (sig)) {
				free (sig);
				sig = strdup ("'wx 10203040");
			}
			char *data = r_core_editor (core, NULL, sig);
			if (data) {
				char *save_ptr = NULL;
				(void) r_str_tok_r (data, ";\n", &save_ptr);
				r_core_cmdf (core, "y%s", data);
				free (data);
			}
			free (sig);
		}
		break;
	case '*': // "y*"
	case 'j': // "yj"
	case '8': // "y8"
	case '\0': // "y"
		r_core_yank_dump (core, 0, input[0]);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_y);
		break;
	default:
		r_core_return_invalid_command (core, "y", *input);
		break;
	}
	return true;
}

