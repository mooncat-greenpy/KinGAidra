#@author mooncat-greenpy
#@category KinGAidra
#@keybinding
#@menupath
#@toolbar

# pyghidraRun + pip install git+https://github.com/mooncat-greenpy/codex-cli-helpers

import json
import os
import threading
import time

import kingaidra
import ghidra.util.task.TaskMonitorAdapter as TaskMonitorAdapter

MODEL = "gpt-5.3-codex"
POST_MSG = ""
TOOLS_FLAG = True

CODEX_BINARY = "codex"
CODEX_WORKDIR = os.environ.get("CODEX_WORKDIR") or os.getcwd()
CODEX_EXTRA_ARGS = ["--sandbox", "read-only"]
CODEX_SESSION_PREFIX = "codex_session:"

KINGAIDRA_MCP_NAME = "ghidra_mcp"
KINGAIDRA_MCP_AUTO = True
KINGAIDRA_MCP_AUTO_WAITTIME = 15


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


def _get_program_identity():
    return currentProgram.getDomainFile().getPathname()


def _hash_identity(value):
    raw = value.encode("utf-8")
    import hashlib
    return hashlib.sha1(raw).hexdigest()


def _resolve_kingaidra_mcp_url():
    try:
        import java.lang.System as JavaSystem
        prop = JavaSystem.getProperty(
            "kingaidra.mcp.url.%s" % _hash_identity(_get_program_identity())
        )
        if prop:
            return prop
    except Exception:
        pass
    return None


def _run_mcp(monitor):
    ghidra = kingaidra.ghidra.GhidraUtilImpl(currentProgram, monitor)
    ghidra.run_script("kingaidra_mcp.py", monitor)


def _mcp_config_args():
    t = None
    monitor = None
    mcp_url = _resolve_kingaidra_mcp_url()
    if TOOLS_FLAG and KINGAIDRA_MCP_AUTO and mcp_url is None:
        monitor = TaskMonitorAdapter(True)
        t = threading.Thread(target=_run_mcp, args=(monitor,))
        t.start()
        time.sleep(KINGAIDRA_MCP_AUTO_WAITTIME)
        mcp_url = _resolve_kingaidra_mcp_url()
    if not TOOLS_FLAG or not mcp_url:
        return [], t, monitor
    return [
        "-c",
        "mcp_servers.%s.url=\"%s\"" % (KINGAIDRA_MCP_NAME, mcp_url),
    ], t, monitor


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

    mcp_args, mcp_thread, mcp_monitor = _mcp_config_args()
    extra_args.extend(mcp_args)

    try:
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
            result = cli.instruct(prompt, extra_args=extra_args)
            if result.returncode != 0:
                raise RuntimeError(_result_error_text(result))
    finally:
        if mcp_thread is not None and mcp_monitor is not None:
            mcp_monitor.cancel()
            mcp_thread.join()

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
