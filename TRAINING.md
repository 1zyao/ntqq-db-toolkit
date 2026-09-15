# 语料 → LoRA → Ollama（macOS）落地说明

`export_messages.py` 产出的东西怎么用起来，按"先能跑、再变好"排。

## 0. 产出物长什么样

| 文件 | 用途 |
| --- | --- |
| `sft_sharegpt.jsonl` | `{"system","conversations":[{from,value}...]}`：LLaMA-Factory / Unsloth / axolotl 通用 |
| `sft_chat.jsonl` | `{"messages":[{role,content}...]}`：mlx-lm、OpenAI 风格微调 |
| `sft_llamacpp.jsonl` | `{"text":"..."}`：llama.cpp `finetune` / 纯文本 SFT |
| `sft_target_<uin>.jsonl` | 只含某个重点会话的样本，可单独看效果 |
| `my_style.txt` | 我的全部独立发言（一行一条），做 few-shot / 检索增强用 |
| `transcripts/*.txt` | 人眼核对用 |

样本构造：以"我的一条文本回复"为答案，前面同会话、同时间窗（默认 1 小时）最多 N 条为上下文。
**每个人的语料都很小**：表情包会吃掉一半发言，最后通常只有几千条，所以别指望从零训练，做 LoRA 就够。

## 1. macOS：MLX LoRA（Apple Silicon，推荐）

```bash
pip install mlx-lm

# 数据目录里放 train.jsonl / valid.jsonl（从 sft_chat.jsonl 切 5% 出来）
mlx_lm.lora \
  --model Qwen/Qwen2.5-1.5B-Instruct \
  --data ./data --train \
  --batch-size 1 --iters 800 --learning-rate 1e-5 \
  --num-layers 8 --max-seq-length 1024 \
  --adapter-path ./adapters

# 融合成一个完整权重
mlx_lm.fuse --model Qwen/Qwen2.5-1.5B-Instruct --adapter-path ./adapters --save-path ./fused
```

## 2. 转成 Ollama 能用的格式

Ollama 只能吃 GGUF。两条路：

```bash
# A. 融合后的全量权重 → GGUF
git clone https://github.com/ggml-org/llama.cpp && cd llama.cpp
pip install -r requirements.txt
python convert_hf_to_gguf.py ../fused --outfile ../qwen-style.gguf --outtype q8_0
ollama create my-style -f Modelfile      # Modelfile: FROM ./qwen-style.gguf

# B. 只带 LoRA 适配器（体积小，需 base 模型相同）
python convert_lora_to_gguf.py ../adapters --base ../Qwen2.5-1.5B-Instruct --outfile ../style-lora.gguf
```

```dockerfile
# Modelfile（B 方案：base + adapter）
FROM qwen2.5:1.5b-instruct
ADAPTER ./style-lora.gguf
PARAMETER temperature 0.9
PARAMETER top_p 0.9
PARAMETER repeat_penalty 1.1
PARAMETER stop "<|im_end|>"
SYSTEM """（用 export_messages.py 生成的那段 system 提示）"""
```

```bash
ollama create my-style -f Modelfile
ollama run my-style "对方：在干嘛？" 
```

## 3. 没有 GPU 时：先别训，先跑通

用 `my_style.txt` 做**检索增强**：把对方最近几条消息与历史对话做相似度检索，取最像的 20~40 条
"对方说了什么 → 我回了什么"塞进 prompt，再让人设 prompt 收尾。任何 API 或本地小模型都能立刻用，
效果通常已经比"硬训一个 0.5B"更像本人。

## 4. 调参经验（短聊天语料）

- 采样要"野"一点：`temperature 0.85~1.0`、`top_p 0.9`、`repeat_penalty 1.05~1.15`；贪心解码会变成复读机。
- 训练轮数别多：这类数据 **1~2 epoch** 就够，多了会把口头禅砸进每一句。
- 生成后处理：去掉换行、去掉句末句号、长度超过 ~30 字就重采样（本人很少长句）。
- 留出集：按**会话**切分（不是按条），否则同一段对话会同时出现在训练/验证里，指标虚高。

## 5. 机器人侧的硬要求（别二次封号）

1. **白名单**：只回指定的人 / 指定会话，群聊默认不回。
2. **限速**：每人每分钟 ≤ 1~2 条，带随机延迟（例如 0.8~3.5s），别秒回。
3. **人工兜底开关**：一条命令停机器人；对方连发/情绪激烈时不回。
4. **别用同一账号做实验**：注入、改客户端、频繁调用接口都是风控目标。
5. **离线优先**：本地模型（Ollama）比调用云端接口更不容易踩到风控/隐私问题。
