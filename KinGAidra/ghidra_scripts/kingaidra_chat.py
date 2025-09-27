#@author mooncat-greenpy
#@category KinGAidra
#@keybinding 
#@menupath 
#@toolbar 


URL = "" # "https://api.openai.com/v1/chat/completions"
MODEL = "" # "gpt-5-mini"
API_KEY = ""
POST_MSG = "" # "Please respond in XXXX."
TOOLS_FLAG = False
OPTIONAL_HEADERS = {}
OPTIONAL_DATA = {}


# Only modify the code above this comment.
# Do not modify the code below this comment.
# The same applies when copying and using this script.


# <KinGAidra Marker For Update: v1.1.0>


import urllib2
import json

import java.util.AbstractMap as AbstractMap
import java.util.LinkedList as LinkedList

import kingaidra

import ghidra.util.task.TaskMonitor as TaskMonitor

def add_tools(data):
    data["tools"] = [
        {
            "type": "function",
            "function": {
                "name": "get_current_address",
                "description": "Returns the user's selected address.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False
                },
                "strict": True
            }
        },
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
                "name": "get_function_list",
                "description": "Retrieve functions in the binary and return their names and addresses.",
                "parameters": {
                    "type": "object",
                    "properties": {
                    },
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_called_function",
                "description": "Retrieve functions that are called by the specified function and return their names and addresses.",
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
                "description": "Retrieve functions that call the specified function and return their names and addresses.",
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
                "name": "get_asm_by_name",
                "description": "Retrieve the assembly code of the specified function.",
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
                "name": "get_decompiled_code_by_name",
                "description": "Retrieve the decompiled code of the specified function in C language.",
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
        },
        {
            "type": "function",
            "function": {
                "name": "add_comments",
                "description": "Adds comments to the specified function based on the provided list.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "number"},
                        "comments": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "source_code_line": {"type": "string"},
                                    "comment": {"type": "string"}
                                },
                                "required": ["source_code_line", "comment"],
                                "additionalProperties": False
                            }
                        }
                    },
                    "required": ["address", "comments"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_strings",
                "description": "Retrieve strings in the binary and their addresses.",
                "parameters": {
                    "type": "object",
                    "properties": {
                    },
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_ref_to",
                "description": "Returns a list of reference source addresses to the specified address.",
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
        }
    ]

def handle_tool_call(tool_call, ghidra):
    func_name = tool_call["function"]["name"]
    args = json.loads(tool_call["function"]["arguments"])
    if func_name == "get_current_address":
        content = "%d" % (ghidra.get_current_addr().getOffset())
    elif func_name == "get_function_address_by_name":
        same_name_funcs = ghidra.get_func(args["name"])
        if not same_name_funcs:
            content = "None"
            return content
        content = "Addresses list.\n"
        for func in same_name_funcs:
            content += "- %d\n" % (func.getEntryPoint().getOffset())
    elif func_name == "get_function_list":
        func_itr = currentProgram.getListing().getFunctions(True)
        content = "Functions list.\n"
        while func_itr.hasNext():
            func = func_itr.next()
            content += "- [%d]: %s\n" % (func.getEntryPoint().getOffset(), func.getName())
    elif func_name == "get_called_function":
        func = ghidra.get_func(ghidra.get_addr(args["address"]))
        if not func:
            content = "Invalid address"
            return content
        called_func_list = func.getCalledFunctions(TaskMonitor.DUMMY)
        if not called_func_list:
            content = "None"
            return content
        content = "Functions list.\n"
        for called_func in called_func_list:
            content += "- [%d]: %s\n" % (called_func.getEntryPoint().getOffset(), called_func.getName())
    elif func_name == "get_calling_function":
        func = ghidra.get_func(ghidra.get_addr(args["address"]))
        if not func:
            content = "Invalid address"
            return content
        calling_func_list = func.getCallingFunctions(TaskMonitor.DUMMY)
        if not calling_func_list:
            content = "None"
            return content
        content = "Functions list.\n"
        for calling_func in calling_func_list:
            content += "- [%d]: %s\n" % (calling_func.getEntryPoint().getOffset(), calling_func.getName())
    elif func_name == "get_asm_by_name":
        same_name_funcs = ghidra.get_func(args["name"])
        if not len(same_name_funcs) == 1:
            content = "Failed"
            return content
        content = ghidra.get_asm(same_name_funcs[0].getEntryPoint())
    elif func_name == "get_asm":
        content = ghidra.get_asm(ghidra.get_addr(args["address"]))
        if not content:
            content = "Invalid address"
            return content
    elif func_name == "get_decompiled_code_by_name":
        same_name_funcs = ghidra.get_func(args["name"])
        if not len(same_name_funcs) == 1:
            content = "Failed"
            return content
        content = ghidra.get_decom(same_name_funcs[0].getEntryPoint())
    elif func_name == "get_decompiled_code":
        content = ghidra.get_decom(ghidra.get_addr(args["address"]))
        if not content:
            content = "Invalid address"
            return content
    elif func_name == "refactoring":
        diff = ghidra.get_decomdiff(ghidra.get_addr(args["address"]))
        if not diff:
            content = "Invalid address"
            return content
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
    elif func_name == "add_comments":
        addr = ghidra.get_addr(args["address"])
        if not addr:
            content = "Invalid address"
            return content
        ghidra.clear_comments(addr)
        comments_list = LinkedList()
        for cmt in args["comments"]:
            comments_list.add(AbstractMap.SimpleEntry(cmt["source_code_line"], cmt["comment"]))
        if ghidra.add_comments(addr, comments_list):
            content = "Success"
        else:
            content = "Failed"
    elif func_name == "get_strings":
        data_list = ghidra.get_strings()
        if not data_list:
            content = "None"
            return
        content = "Strings list.\n"
        for data in data_list:
            content += "- [%d]: %s\n" % (data.getAddress().getOffset(), data.getDefaultValueRepresentation())
    elif func_name == "get_ref_to":
        ref_list = ghidra.get_ref_to(ghidra.get_addr(args["address"]))
        if not ref_list:
            content = "None"
            return
        content = "Reference address.\n"
        for ref in ref_list:
            content += "- %d\n" % (ref.getFromAddress().getOffset())
    if not content:
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

    if (type == kingaidra.ai.task.TaskType.CHAT_EXPLAIN_DECOM.toString() or
        type == kingaidra.ai.task.TaskType.CHAT_EXPLAIN_ASM.toString() or
        type == kingaidra.ai.task.TaskType.CHAT_DECOM_ASM.toString() or
        type == kingaidra.ai.task.TaskType.CHAT_EXPLAIN_STRINGS.toString() or
        type == kingaidra.ai.task.TaskType.ADD_COMMENTS.toString()):
        data["messages"][-1]["content"] += POST_MSG

    while True:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + API_KEY,
            "User-Agent": "Python",
        }
        headers.update(OPTIONAL_HEADERS)
        data.update(OPTIONAL_DATA)
        req = urllib2.Request(
            URL,
            json.dumps(data),
            headers
        )

        try:
            response = json.loads(urllib2.urlopen(req).read())
        except urllib2.HTTPError as e:
            printerr(str(e))
            printerr(e.read())
            exit()

        data["messages"].append(response["choices"][0]["message"])
        if response["choices"][0]["finish_reason"] == "tool_calls":
            for i in response["choices"][0]["message"]["tool_calls"]:
                try:
                    content = handle_tool_call(i, ghidra)
                except Exception as e:
                    content = "Failed"
                data["messages"].append({"role": "tool", "tool_call_id": i["id"], "content": content})
        elif response["choices"][0]["finish_reason"] == "stop":
            break
    result = response["choices"][0]["message"]["content"]

    state.addEnvironmentVar("RESPONSE", result)

if __name__ == "__main__":
    TOOLS_FLAG = globals().get("TOOLS_FLAG", True)
    main()
