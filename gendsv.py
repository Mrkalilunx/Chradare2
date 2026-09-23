import re

"""
manr2 翻译表生成器
从 manr2dict.h 提取三张表导出 manr2.tsv,供插件运行时加载
用法: python3 gendsv.py -> 生成 manr2.tsv,若源表缺省则保留原文件

manr2.tsv 每行三列:类型\ten\tzh
- u  用法行参数段(Usage: 之后的整段文本)
- d  行内说明或整行标题
- a  含方括号的参数占位符
配套 manr2ext.tsv 同构,收第三方插件(r2dec/ghidra/pseudo)词条,后者覆盖前者
"""


def cesc_un(s):
    out = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == '\\' and i + 1 < n:
            c = s[i + 1]
            i += 2
            if c == 'n':
                out.append('\n')
            elif c == 't':
                out.append('\t')
            elif c == 'r':
                out.append('\r')
            elif c == '?':
                out.append('?')
            elif c == '"':
                out.append('"')
            elif c == '\\':
                out.append('\\')
            elif c == 'x' and i + 2 <= n:
                out.append(chr(int(s[i:i + 2], 16)))
                i += 2
            else:
                out.append(c)
        else:
            out.append(s[i])
            i += 1
    return ''.join(out)


def parse_arr(src, name):
    m = re.search(name + r'\[\]\s*=\s*\{(.*?)\n\};', src, re.S)
    out = []
    if m:
        for e in re.finditer(r'\{\s*"(.*?)"\s*,\s*"(.*?)"\s*\}', m.group(1)):
            out.append((cesc_un(e.group(1)), cesc_un(e.group(2))))
    return out


def write_tsv(path, rows):
    lines = []
    for t, rows2 in rows:
        for en, zh in rows2:
            e = en.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')
            z = zh.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')
            lines.append(f"{t}\t{e}\t{z}")
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f"{path}: {len(lines)} 条")
    return len(lines)


def main():
    src = open('manr2dict.h', encoding='utf-8').read()
    u = parse_arr(src, 'manr2usage')
    d = parse_arr(src, 'manr2dict')
    a = parse_arr(src, 'manr2argtab')
    write_tsv('manr2.tsv', [('u', u), ('d', d), ('a', a)])


if __name__ == '__main__':
    main()