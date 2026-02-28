#@runtime PyGhidra
#@author mooncat-greenpy
#@category KinGAidra
#@keybinding
#@menupath
#@toolbar

# pyghidraRun + pip install git+https://github.com/mooncat-greenpy/codex-cli-helpers


import os

MODEL = "gpt-5.3-codex"
MODEL_REASONING_EFFORT = "xhigh" # e.g. "high", "medium"
POST_MSG = ""
TOOLS_FLAG = True

CODEX_BINARY = "codex"
CODEX_WORKDIR = os.environ.get("CODEX_WORKDIR") or os.path.join(os.getcwd(), "codex_dir")
CODEX_EXTRA_ARGS = ["--sandbox", "read-only"]
CODEX_SESSION_PREFIX = "codex_session:"

KINGAIDRA_MCP_NAME = "ghidra_mcp"


# Only modify the code above this comment.
# Do not modify the code below this comment.
# The same applies when copying and using this script.


# <KinGAidra Marker For Update: kingaidra_chat_codex.py v1.1.0>


import kingaidra
import json

def _load_codex_cli():
    try:
        from codex_cli_helpers import CodexCLI
    except ImportError:
        raise ImportError(
            "codex_cli_helpers is required. Install with: "
            "pip install git+https://github.com/mooncat-greenpy/codex-cli-helpers"
        )
    return CodexCLI


def _to_json_text(value):
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


def _map_log_message(msg, idx):
    role = getattr(msg, "role", "")
    kind = getattr(msg, "kind", "")
    text = getattr(msg, "text", "")
    payload = getattr(msg, "payload", {})
    item = payload.get("item", {})

    if role == "user":
        return None

    if kind == "tool_call":
        call_id = payload.get("call_id")
        name = payload.get("name", "tool_call")
        args = payload.get("arguments")
        mapped = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": _to_json_text(args),
                    },
                }
            ],
        }
        return mapped

    if kind == "tool_output":
        call_id = payload.get("call_id")
        mapped = {
            "role": "tool",
            "content": text,
        }
        if call_id:
            mapped["tool_call_id"] = str(call_id)
        return mapped

    if role == "assistant" or kind in ("assistant_message", "thinking"):
        return {"role": "assistant", "content": text}
    if role == "tool":
        return {"role": "tool", "content": text}
    return None


def _messages_from_log_messages(log_messages):
    msgs = sorted(log_messages, key=lambda m: m.timestamp)
    out = []
    for i, msg in enumerate(msgs):
        mapped = _map_log_message(msg, i)
        if mapped is None:
            continue
        out.append(mapped)
    return out


def _encode_session_marker(session_id):
    return "%s%s" % (CODEX_SESSION_PREFIX, session_id)


def _decode_session_marker(marker):
    if marker is None:
        return None
    text = str(marker)
    if not text.startswith(CODEX_SESSION_PREFIX):
        return None
    return text[len(CODEX_SESSION_PREFIX):]


def _find_latest_session_id(messages):
    for msg in reversed(messages):
        if not isinstance(msg, dict):
            continue
        session_id = _decode_session_marker(msg.get("tool_call_id"))
        if session_id:
            return session_id
    return None


def _attach_session_marker(messages, session_id):
    marker = _encode_session_marker(session_id)
    for msg in reversed(messages):
        if not isinstance(msg, dict):
            continue
        if msg.get("role") == "assistant":
            msg["tool_call_id"] = marker
            return
    messages.append({"role": "assistant", "content": "", "tool_call_id": marker})


def _get_chat_task_service():
    tool = state.getTool()
    if tool is None:
        return None
    return tool.getService(kingaidra.ai.task.KinGAidraChatTaskService)


def _ensure_kingaidra_mcp_url():
    service = _get_chat_task_service()
    if service is None:
        return None
    url = service.ensure_mcp_server_url()
    if url:
        return str(url)
    return None


def _mcp_config_args():
    if not TOOLS_FLAG:
        return []
    mcp_url = _ensure_kingaidra_mcp_url()
    if not mcp_url:
        return []
    return [
        "-c",
        "mcp_servers.%s.url=\"%s\"" % (KINGAIDRA_MCP_NAME, mcp_url),
    ]


def _result_error_text(result):
    if result is None:
        return "unknown error"
    err = (result.stderr or "").strip()
    out = (result.stdout or "").strip()
    if err:
        return err
    if out:
        return out
    return "returncode=%s" % result.returncode


def _resume_extra_args(extra_args):
    out = []
    i = 0
    while i < len(extra_args):
        token = extra_args[i]
        if token == "--sandbox":
            i += 1
            if i < len(extra_args) and not extra_args[i].startswith("-"):
                i += 1
            continue
        out.append(token)
        i += 1
    return out


def main():
    task_type = state.getEnvironmentVar("TYPE")
    messages = json.loads(state.getEnvironmentVar("MESSAGES"))

    if (task_type == kingaidra.ai.task.TaskType.CHAT_EXPLAIN_DECOM.toString() or
        task_type == kingaidra.ai.task.TaskType.CHAT_EXPLAIN_ASM.toString() or
        task_type == kingaidra.ai.task.TaskType.CHAT_DECOM_ASM.toString() or
        task_type == kingaidra.ai.task.TaskType.CHAT_EXPLAIN_STRINGS.toString() or
        task_type == kingaidra.ai.task.TaskType.ADD_COMMENTS.toString()):
        messages[-1]["content"] += "\n\n" + POST_MSG

    CodexCLI = _load_codex_cli()
    prev_session_id = _find_latest_session_id(messages)

    cli = CodexCLI(
        binary=CODEX_BINARY,
        workdir=CODEX_WORKDIR,
        prefer_workdir_codex_home=True,
    )

    extra_args = CODEX_EXTRA_ARGS
    extra_args.extend(["--model", MODEL])
    if MODEL_REASONING_EFFORT:
        extra_args.extend(
            ["-c", "model_reasoning_effort=%s" % MODEL_REASONING_EFFORT]
        )

    mcp_args = _mcp_config_args()
    extra_args.extend(mcp_args)

    if prev_session_id:
        result = cli.resume(
            session_id=prev_session_id,
            prompt=messages[-1]["content"],
            extra_args=_resume_extra_args(extra_args),
        )
        if result.returncode != 0:
            raise RuntimeError(_result_error_text(result))
    else:
        prompt = ""
        if len(messages) == 1:
            prompt = messages[-1]["content"]
        else:
            for msg in messages:
                prompt += msg["role"] + ": " + msg["content"] + "\n"
        result = cli.instruct(prompt, extra_args=extra_args, use_stdin=True)
        if result.returncode != 0:
            raise RuntimeError(_result_error_text(result))

    session_id = result.session_id or prev_session_id

    log = cli.load_session_log(session_id)
    messages_out = _messages_from_log_messages(log.messages())
    response = result.last_agent_text()

    if session_id:
        _attach_session_marker(messages_out, session_id)

    state.addEnvironmentVar("RESPONSE", response)
    state.addEnvironmentVar("MESSAGES_OUT", json.dumps(messages_out, ensure_ascii=False))


if __name__ == "__main__":
    main()
