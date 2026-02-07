#@author mooncat-greenpy
#@category KinGAidra
#@keybinding
#@menupath
#@toolbar

# pyghidraRun + pip install langchain langchain-mcp-adapters langchain-openai

import kingaidra

import json
import asyncio

from langchain_openai import ChatOpenAI
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain.agents import create_agent


URL = "" # "https://api.openai.com/v1"
MODEL = ""  # "gpt-5.2"
API_KEY = ""
POST_MSG = ""  # "Please respond in XXXX."
TOOLS_FLAG = True
OPTIONAL_HEADERS = {}
OPTIONAL_DATA = {}

MCP_URL = "http://localhost:8000/mcp"
MCP_SERVER_NAME = "ghidra_mcp"
MCP_TRANSPORT = "http"


def _init_llm():
    model = ChatOpenAI(
        model=MODEL,
        api_key=API_KEY,
        base_url=URL,
        # temperature=...,
        # max_tokens=...,
        # timeout=...,
        # max_retries=...,
        # reasoning_effort=...,
        # model_kwargs=...,
        # extra_body=...,
    )
    return model

def _init_mcp_tools():
    client = MultiServerMCPClient(
        {
            MCP_SERVER_NAME: {
                "transport": MCP_TRANSPORT,
                "url": MCP_URL,
            }
            # ...
        }
    )
    return asyncio.run(client.get_tools())


# Only modify the code above this comment.
# Do not modify the code below this comment.


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
        tools = _init_mcp_tools()
    model = _init_llm()

    import httpx
    if OPTIONAL_HEADERS:
        model.http_client = httpx.Client(headers=OPTIONAL_HEADERS)
        model.http_async_client = httpx.AsyncClient(headers=OPTIONAL_HEADERS)

    agent = create_agent(model, tools=tools)

    resp = tools = asyncio.run(agent.ainvoke({"messages": data["messages"]}))


    result = resp["messages"][-1].content

    state.addEnvironmentVar("RESPONSE", result)


if __name__ == "__main__":
    main()
