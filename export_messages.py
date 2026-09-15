#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把明文 nt_msg.db 导出成可读转录 + 微调语料。

要点：正文必须按 `content_type(45002)==1` 取 `text(45101)`，表情取 `text_fallback(45815)`。
把所有 length-delimited 字段都当文本的土办法会把 sender_uid / ext_proto_ver 之类拼进正文。

用法
----
    python export_messages.py --db plain.db --out corpus
    python export_messages.py --db plain.db --out corpus --target-uin 10001 \
        --max-ctx 12 --window 3600

输出（<out>/）
    transcripts/<conv>.txt     每个会话的可读转录
    my_texts.jsonl             我发出的全部文本（带会话 / 时间）
    my_style.txt               我的独立文本（去重，一行一条）
    sft_sharegpt.jsonl         ShareGPT 风格（LLaMA-Factory / Unsloth）
    sft_chat.jsonl             {"messages":[...]}（mlx-lm / OpenAI 风格）
    sft_llamacpp.jsonl         {"text": "..."}（llama.cpp finetune）
    sft_target_<uin>.jsonl     只含指定会话的样本
    stats.txt                  统计
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sqlite3
import sys
import time

try:                       # Windows 控制台默认 GBK，中文输出会乱码
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:          # noqa: BLE001
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ntmsg_wire import message_view                              # noqa: E402

DEFAULT_SYSTEM = (
    '你在用手机QQ和好友聊天。你要模仿账号 {uin} 本人的说话风格，直接发出这条回复。\n'
    '要求：\n'
    '1. 口语化、短句为主，通常一句话，不打官腔、不解释、不总结；\n'
    '2. 可以带网络语气词、谐音、口头禅、[表情] 标记，极少使用标点；\n'
    '3. 不要自称AI、不要复述对方的话、不要说教；\n'
    '4. 只用中文（含表情标记），长度与平时发言相当。'
)

AT_LINE = re.compile(r'^@[^\s]{1,24}\s*$')
TABLES = (('c2c_msg_table', False), ('group_msg_table', True))
SELECT = ('SELECT "40001","40050","40013","40020","40033","40021","40030","40011","40090","40800"'
          ' FROM "%s" WHERE "40800" IS NOT NULL ORDER BY "40050","40001"')


def clean_text(t: str) -> str:
    if not t:
        return ''
    keep = []
    for ln in t.replace('\r', '').split('\n'):
        ln = ln.strip()
        if ln and not AT_LINE.match(ln):
            keep.append(ln)
    return re.sub(r'[ \t]{2,}', ' ', '\n'.join(keep)).strip()


def load_messages(con, uin: str):
    msgs = collections.defaultdict(list)
    n = 0
    for table, is_group in TABLES:
        for row in con.execute(SELECT % table):
            _mid, ts, direction, suid, sqq, puid, pqq, mtype, nick, blob = row
            kind, text = message_view(blob, mtype or 0)
            if kind not in ('text', 'sticker'):
                continue
            text = clean_text(text)
            if kind == 'sticker' and not text:
                text = '[表情]'
            if not text:
                continue
            conv = ('group_%s' % puid) if is_group else ('c2c_%s' % pqq)
            msgs[conv].append(dict(mid=_mid, ts=ts or 0, me=(direction or 0) == 1,
                                   kind=kind, text=text, nick=nick or ''))
            n += 1
    return msgs, n


def wrap(template: str, system: str, human: str, gpt: str) -> str:
    if template == 'qwen':
        return ('<|im_start|>system\n%s<|im_end|>\n<|im_start|>user\n%s<|im_end|>\n'
                '<|im_start|>assistant\n%s<|im_end|>\n' % (system, human, gpt))
    if template == 'llama3':
        return ('<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n%s'
                '<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n%s<|eot_id|>'
                '<|start_header_id|>assistant<|end_header_id|>\n\n%s<|eot_id|>'
                % (system, human, gpt))
    return '%s\n\n【聊天记录】\n%s\n\n【我的回复】\n%s' % (system, human, gpt)


def main() -> int:
    ap = argparse.ArgumentParser(description='NTQQ 明文库 → 转录 + 微调语料')
    ap.add_argument('--db', required=True, help='已解密的 nt_msg.db')
    ap.add_argument('--out', required=True)
    ap.add_argument('--uin', default='<uin>', help='账号（写进 system 提示）')
    ap.add_argument('--target-uin', action='append', default=[],
                    help='重点会话的对端 uin（可多次指定）')
    ap.add_argument('--window', type=int, default=3600, help='上下文时间窗（秒）')
    ap.add_argument('--max-ctx', type=int, default=12, help='上下文最多几条')
    ap.add_argument('--min-ctx', type=int, default=1)
    ap.add_argument('--template', default='none', choices=['none', 'qwen', 'llama3'])
    ap.add_argument('--no-transcripts', action='store_true')
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    if not a.no_transcripts:
        os.makedirs(os.path.join(a.out, 'transcripts'), exist_ok=True)
    system = DEFAULT_SYSTEM.format(uin=a.uin)

    con = sqlite3.connect('file:%s?mode=ro' % a.db, uri=True)
    msgs, n_msg = load_messages(con, a.uin)
    con.close()

    f_my = open(os.path.join(a.out, 'my_texts.jsonl'), 'w', encoding='utf-8')
    f_style = open(os.path.join(a.out, 'my_style.txt'), 'w', encoding='utf-8')
    f_share = open(os.path.join(a.out, 'sft_sharegpt.jsonl'), 'w', encoding='utf-8')
    f_chat = open(os.path.join(a.out, 'sft_chat.jsonl'), 'w', encoding='utf-8')
    f_cpp = open(os.path.join(a.out, 'sft_llamacpp.jsonl'), 'w', encoding='utf-8')
    f_tgt = {u: open(os.path.join(a.out, 'sft_target_%s.jsonl' % u), 'w', encoding='utf-8')
             for u in a.target_uin}

    n_me = n_sft = 0
    seen = set()
    per_conv = []
    for conv, lst in sorted(msgs.items(), key=lambda kv: -len(kv[1])):
        lst.sort(key=lambda m: (m['ts'], m['mid']))
        if not a.no_transcripts:
            with open(os.path.join(a.out, 'transcripts', '%s.txt' % conv), 'w',
                      encoding='utf-8') as f:
                for m in lst:
                    f.write('[%s] %s: %s\n' % (
                        time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(m['ts'])),
                        '我' if m['me'] else '对方', m['text']))
        for m in lst:
            if not m['me']:
                continue
            n_me += 1
            f_my.write(json.dumps({'conv': conv, 'ts': m['ts'], 'kind': m['kind'],
                                   'text': m['text']}, ensure_ascii=False) + '\n')
            if m['text'] not in seen:
                seen.add(m['text'])
                f_style.write(m['text'] + '\n')

        for i, m in enumerate(lst):
            if not m['me'] or m['kind'] != 'text':
                continue
            ctx = []
            for j in range(i - 1, -1, -1):
                if m['ts'] - lst[j]['ts'] > a.window:
                    break
                ctx.append(lst[j])
                if len(ctx) >= a.max_ctx:
                    break
            ctx.reverse()
            if len(ctx) < a.min_ctx or all(c['me'] for c in ctx):
                continue
            human = '\n'.join('%s: %s' % ('我' if c['me'] else '对方', c['text']) for c in ctx)
            share = {'system': system,
                     'conversations': [{'from': 'human', 'value': human},
                                       {'from': 'gpt', 'value': m['text']}],
                     'meta': {'conv': conv, 'ts': m['ts']}}
            line = json.dumps(share, ensure_ascii=False) + '\n'
            f_share.write(line)
            f_chat.write(json.dumps({'messages': [
                {'role': 'system', 'content': system},
                {'role': 'user', 'content': human},
                {'role': 'assistant', 'content': m['text']}]}, ensure_ascii=False) + '\n')
            f_cpp.write(json.dumps({'text': wrap(a.template, system, human, m['text'])},
                                   ensure_ascii=False) + '\n')
            n_sft += 1
            for u in a.target_uin:
                if conv == 'c2c_%s' % u:
                    f_tgt[u].write(line)
        per_conv.append((conv, len(lst), sum(1 for x in lst if x['me'])))

    for f in (f_my, f_style, f_share, f_chat, f_cpp, *f_tgt.values()):
        f.close()

    lines = ['来源: %s' % a.db,
             '会话数: %d' % len(msgs),
             '可用消息: %d' % n_msg,
             '我的消息: %d' % n_me,
             '我的独立文本: %d' % len(seen),
             'SFT 样本: %d' % n_sft,
             '上下文: 窗口 %ds / 最多 %d 条' % (a.window, a.max_ctx),
             '', 'Top 会话（会话, 总条数, 我的条数）:']
    for c, tot, me in sorted(per_conv, key=lambda x: -x[2])[:25]:
        lines.append('  %-24s %6d %6d' % (c, tot, me))
    with open(os.path.join(a.out, 'stats.txt'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print('\n'.join(lines).encode('ascii', 'replace').decode('ascii'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
