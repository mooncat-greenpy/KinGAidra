#@author mooncat-greenpy
#@category KinGAidra
#@keybinding 
#@menupath 
#@toolbar 


URL = "" # "https://api.openai.com/v1/chat/completions"
MODEL = "" # "gpt-4o-mini"
API_KEY = ""
POST_MSG = "" # "Please respond in XXXX."
TOOLS_FLAG = True


# Only modify the code above this comment.
# Do not modify the code below this comment.
# The same applies when copying and using this script.


# <KinGAidra Marker For Update: v1.1.0>


import kingaidra

import urllib2
import json

import ghidra.util.task.TaskMonitor as TaskMonitor

def add_tools(data):
    data["tools"] = [
        {
            "type": "function",
            "function": {
                "name": "get_function_address_by_name",
                "description": "Retrieve the address of a function by its name. If multiple functions have the same name, return a list of addresses.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                    },
                    "required": ["name"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_called_function",
                "description": "Retrieve functions that are called by the specified function.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "number"},
                    },
                    "required": ["address"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_calling_function",
                "description": "Retrieve functions that call the specified function.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "number"},
                    },
                    "required": ["address"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_asm",
                "description": "Retrieve the assembly code of the specified function.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "number"},
                    },
                    "required": ["address"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_decompiled_code",
                "description": "Retrieve the decompiled code of the specified function in C language.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "number"},
                    },
                    "required": ["address"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "refactoring",
                "description": "Refactoring the decompiled code of the specified function in C language.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "number"},
                        "new_func_name": {"type": "string"},
                        "params": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "orig_param_name": {"type": "string"},
                                    "new_param_name": {"type": "string"},
                                    "new_datatype": {"type": "string"}
                                },
                                "required": ["orig_param_name", "new_param_name", "new_datatype"],
                                "additionalProperties": False
                            }
                        },
                        "variables": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "orig_var_name": {"type": "string"},
                                    "new_var_name": {"type": "string"},
                                    "new_datatype": {"type": "string"}
                                },
                                "required": ["orig_var_name", "new_var_name", "new_datatype"],
                                "additionalProperties": False
                            }
                        },
                    },
                    "required": ["address", "new_func_name", "params", "variables"],
                    "additionalProperties": False
                },
                "strict": True
            }
        }
    ]

def handle_tool_call(tool_call, ghidra):
    func_name = tool_call["function"]["name"]
    args = json.loads(tool_call["function"]["arguments"])
    if func_name == "get_function_address_by_name":
        same_name_funcs = ghidra.get_func(args["name"])
        content = "Address list.\n"
        for func in same_name_funcs:
            content += "- %d\n" % (func.getEntryPoint().getOffset())
    elif func_name == "get_called_function":
        func = ghidra.get_func(ghidra.get_addr(args["address"]))
        content = ""
        for calling_func in func.getCalledFunctions(TaskMonitor.DUMMY):
            content += "- [%d]: %s\n" % (calling_func.getEntryPoint().getOffset(), calling_func.getName())
    elif func_name == "get_calling_function":
        func = ghidra.get_func(ghidra.get_addr(args["address"]))
        content = ""
        for calling_func in func.getCallingFunctions(TaskMonitor.DUMMY):
            content += "- [%d]: %s\n" % (calling_func.getEntryPoint().getOffset(), calling_func.getName())
    elif func_name == "get_asm":
        content = ghidra.get_asm(ghidra.get_addr(args["address"]))
    elif func_name == "get_decompiled_code":
        content = ghidra.get_decom(ghidra.get_addr(args["address"]))
    elif func_name == "refactoring":
        diff = ghidra.get_decomdiff(ghidra.get_addr(args["address"]))
        diff.set_name(args["new_func_name"])
        for param in args["params"]:
            diff.set_param_new_name(param["orig_param_name"], param["new_param_name"])
            diff.set_datatype_new_name(param["orig_param_name"], param["new_datatype"])
        for var in args["variables"]:
            diff.set_var_new_name(var["orig_var_name"], var["new_var_name"])
            diff.set_datatype_new_name(var["orig_var_name"], var["new_datatype"])
        if ghidra.refact(diff):
           content = "Success"
        else:
           content = "Failed"
    return content

def main():
    ghidra = kingaidra.ghidra.GhidraUtilImpl(currentProgram, TaskMonitor.DUMMY)
    data = {
        "model": MODEL,
        "messages": []
    }
    if TOOLS_FLAG:
        add_tools(data)

    type = state.getEnvironmentVar("TYPE")
    data["messages"] = json.loads(state.getEnvironmentVar("MESSAGES"))

    if type == kingaidra.ai.task.TaskType.CHAT.toString() or type == kingaidra.ai.task.TaskType.ADD_COMMENTS.toString():
        data["messages"][-1]["content"] += POST_MSG

    while True:
        req = urllib2.Request(
            URL,
            json.dumps(data),
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + API_KEY,
                "User-Agent": "Python",
            }
        )
        response = json.loads(urllib2.urlopen(req).read())

        data["messages"].append(response["choices"][0]["message"])

        if response["choices"][0]["finish_reason"] == "tool_calls":
            for i in response["choices"][0]["message"]["tool_calls"]:
                content = handle_tool_call(i, ghidra)
                data["messages"].append({"role": "tool", "tool_call_id": i["id"], "content": content})
        elif response["choices"][0]["finish_reason"] == "stop":
            break
    result = response["choices"][0]["message"]["content"]

    state.addEnvironmentVar("RESPONSE", result)

if __name__ == "__main__":
    main()
