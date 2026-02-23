#@author mooncat-greenpy
#@category KinGAidra
#@keybinding
#@menupath
#@toolbar

# pyghidraRun + pip install langchain langchain-mcp-adapters langchain-openai langgraph

import kingaidra

import os
import json
import asyncio

from langchain_openai import ChatOpenAI
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain.agents import create_agent
from langchain_core.messages import convert_to_messages, messages_to_dict as _messages_to_dict
from langgraph.checkpoint.memory import InMemorySaver

URL = "https://api.openai.com/v1" # e.g. "http://localhost:8000/v1"
MODEL = "gpt-5.2" # e.g. "gpt-oss:120b"
API_KEY = os.environ.get("OPENAI_API_KEY", "")
POST_MSG = ""  # e.g. "Please respond in XXXX."
TOOLS_FLAG = True
OPTIONAL_HEADERS = {}
OPTIONAL_DATA = {}

KINGAIDRA_MCP_NAME = "ghidra_mcp"
KINGAIDRA_MCP_TRANSPORT = "http"

def _init_llm():
    model = ChatOpenAI(
        model=MODEL,
        api_key=API_KEY,
        base_url=URL,
        max_retries=5,
        # temperature=...,
        # max_tokens=...,
        # timeout=...,
        # reasoning_effort=...,
        # model_kwargs=...,
        # extra_body=...,
    )
    return model

def _init_mcp_tools(kingaidra_mcp_url):
    connections = {
        # ...
    }
    print("KinGAidra MCP URL:", kingaidra_mcp_url)
    if kingaidra_mcp_url:
        connections[KINGAIDRA_MCP_NAME] = {
            "transport": KINGAIDRA_MCP_TRANSPORT,
            "url": kingaidra_mcp_url,
        }
    client = MultiServerMCPClient(
        connections,
        tool_name_prefix=True,
    )
    return asyncio.run(client.get_tools())

def _create_agent(model, tools, thread_id):
    checkpointer = InMemorySaver()
    agent = create_agent(model, tools=tools, checkpointer=checkpointer)
    config = {"configurable": {"thread_id": thread_id}}
    return agent, config


# Only modify the code above this comment.
# Do not modify the code below this comment.


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

def _tool_args_to_str(args):
    if args is None:
        return ""
    if isinstance(args, str):
        return args
    try:
        return json.dumps(args, ensure_ascii=False)
    except Exception:
        return str(args)

def _normalize_tool_call(call):
    if not isinstance(call, dict):
        return call
    if "function" in call:
        return call
    name = call.get("name")
    args = call.get("args")
    call_id = call.get("id") or call.get("tool_call_id")
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": _tool_args_to_str(args),
        },
    }

def _extract_tool_result(data):
    if not isinstance(data, dict):
        return ""
    try:
        result = data.get("artifact", {}).get("structured_content", {}).get("result")
        if result:
            return result
    except Exception:
        pass
    content = data.get("content")
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                text = item.get("text")
                if text is not None:
                    parts.append(text)
            elif isinstance(item, str):
                parts.append(item)
        return "".join(parts)
    if content is None:
        return ""
    return str(content)

def messages_to_dict(messages):
    msgs = _messages_to_dict(messages)
    for msg in msgs:
        if not isinstance(msg, dict):
            continue
        msg_type = msg.get("type")
        data = msg.get("data")
        if msg_type == "ai" and isinstance(data, dict):
            tool_calls = data.get("tool_calls")
            if isinstance(tool_calls, list):
                data["tool_calls"] = [_normalize_tool_call(c) for c in tool_calls]
            else:
                additional = data.get("additional_kwargs")
                if isinstance(additional, dict) and isinstance(additional.get("tool_calls"), list):
                    additional["tool_calls"] = [_normalize_tool_call(c) for c in additional["tool_calls"]]
        elif msg_type == "tool" and isinstance(data, dict):
            data["content"] = _extract_tool_result(data)
    return msgs

def main():
    data = {
        "messages": []
    }

    type = state.getEnvironmentVar("TYPE")
    data["messages"] = json.loads(state.getEnvironmentVar("MESSAGES"))

    if (type == kingaidra.ai.task.TaskType.CHAT_EXPLAIN_DECOM.toString() or
        type == kingaidra.ai.task.TaskType.CHAT_EXPLAIN_ASM.toString() or
        type == kingaidra.ai.task.TaskType.CHAT_DECOM_ASM.toString() or
        type == kingaidra.ai.task.TaskType.CHAT_EXPLAIN_STRINGS.toString() or
        type == kingaidra.ai.task.TaskType.ADD_COMMENTS.toString()):
        data["messages"][-1]["content"] += "\n\n" + POST_MSG


    tools = []
    if TOOLS_FLAG:
        kingaidra_mcp_url = _ensure_kingaidra_mcp_url()
        tools = _init_mcp_tools(kingaidra_mcp_url)
    model = _init_llm()

    import httpx
    if OPTIONAL_HEADERS:
        model.http_client = httpx.Client(headers=OPTIONAL_HEADERS)
        model.http_async_client = httpx.AsyncClient(headers=OPTIONAL_HEADERS)

    thread_id = state.getEnvironmentVar("KEY") or "kingaidra"
    agent, agent_config = _create_agent(model, tools, thread_id)

    input_messages = convert_to_messages(data["messages"])
    if agent_config is None:
        resp = asyncio.run(agent.ainvoke({"messages": input_messages}))
    else:
        resp = asyncio.run(agent.ainvoke({"messages": input_messages}, agent_config))

    result = resp["messages"][-1].content

    state.addEnvironmentVar("RESPONSE", result)
    state.addEnvironmentVar("MESSAGES_OUT", json.dumps(messages_to_dict(resp["messages"]), default=str))

if __name__ == "__main__":
    main()
