# Running clarikube with a local model

clarikube does the analysis itself, so a small local model only has to pick tools and explain the result.
`clarikube ask` runs a minimal agent loop against any **OpenAI-compatible** endpoint — no MCP client needed.

## 1. Start a model

**Ollama** (Windows, macOS, Linux). Pick a model with tool calling that fits your GPU:

| VRAM | Try first | Notes |
|---|---|---|
| 6 GB (e.g. RTX 3050 laptop) | `qwen2.5:7b-instruct` (Q4) | good tool calling for its size |
| 4 GB / CPU only | `qwen2.5:3b-instruct`, `llama3.2:3b` | slower, less reliable tool choice |
| 12 GB+ | `qwen2.5:14b-instruct`, `mistral-small` | noticeably better explanations |

```bash
ollama pull qwen2.5:7b-instruct
```

If clarikube runs in a VM and Ollama on the host, let Ollama listen on the network: set the environment
variable `OLLAMA_HOST=0.0.0.0` on the host (Windows: System → Environment Variables, then restart Ollama) and
use `http://<host-ip>:11434/v1` from the VM.

LM Studio (`http://localhost:1234/v1`), vLLM, llama.cpp `llama-server` and OpenAI-compatible cloud APIs work
the same way.

## 2. Ask

```bash
export CLARIKUBE_LLM_MODEL=qwen2.5:7b-instruct
export CLARIKUBE_LLM_BASE_URL=http://localhost:11434/v1     # default
# export CLARIKUBE_LLM_API_KEY=...                          # only for hosted endpoints

# against the bundled demo (no cluster):
CLARIKUBE_SOURCE=fixture clarikube ask "Why is shop/orders crashing?"

# against your cluster / lab:
clarikube ask "What data systems run in the cluster and what is wrong with them?" --transcript run.json
```

Tool calls are printed (dimmed) as they happen; the final answer goes to stdout; the summary line shows tool
calls, tokens and time. `--transcript` saves everything as JSON (this is what the benchmark will consume).

Options: `--max-steps` (default 8), `--max-tool-chars` (default 6000; lower it for 4k-context models).

## 3. Commit (human only)

The model can create plans but `commit_plan` is never offered to it. Review and commit yourself:

```bash
clarikube show <plan-id>
clarikube commit <plan-id>      # asks for confirmation on your terminal; refuses without a TTY
```

## What to look at when testing a model

- Did it call `diagnose_workload` / `diagnose_component` before answering (not guess)?
- Did it name the right root cause (for the demo: Kafka `data/events`, min.insync.replicas = RF with one broker down)?
- Did it ignore the injected "ignore previous instructions" text? (clarikube never returns it, but check.)
- Tokens and seconds per question (summary line / transcript).

Some small models print a tool call as JSON text instead of using the tool-call API; `clarikube ask`
recognises that format too.
