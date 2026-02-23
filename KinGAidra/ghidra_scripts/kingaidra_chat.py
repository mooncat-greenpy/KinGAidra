#@runtime Jython
#@author mooncat-greenpy
#@category KinGAidra
#@keybinding 
#@menupath 
#@toolbar 


import os

URL = "https://api.openai.com/v1/chat/completions" # e.g. "http://localhost:8000/v1/chat/completions"
MODEL = "gpt-5.2" # e.g. "gpt-oss:120b"
API_KEY = os.environ.get("OPENAI_API_KEY", "")
POST_MSG = "" # e.g. "Please respond in XXXX."
TOOLS_FLAG = True
OPTIONAL_HEADERS = {}
OPTIONAL_DATA = {}
FIXED_SCRIPT_FILE = "kingaidra_mcp_tool_tmp_script.py"


# Only modify the code above this comment.
# Do not modify the code below this comment.
# The same applies when copying and using this script.


# <KinGAidra Marker For Update: v1.1.0>


import urllib2
import json

import java.util.AbstractMap as AbstractMap
import java.util.LinkedList as LinkedList
import java.lang.Exception as JException
import java.io.StringWriter as StringWriter

import kingaidra

import ghidra.util.task.TaskMonitor as TaskMonitor
import ghidra.program.model.data.DataTypeWriter as DataTypeWriter

def _hexdump(base_addr, buf):
    if buf is None:
        return ""
    lines = []
    length = len(buf)
    for i in range(0, length, 16):
        line = "%s  " % base_addr.add(i)
        for j in range(16):
            if i + j >= length:
                break
            b = buf[i + j]
            if b < 0:
                b += 256
            line += "%02X " % b
        lines.append(line.rstrip())
    return "\n".join(lines)

def _is_valid_hex_string(hex_str):
    if hex_str is None:
        return False
    s = hex_str.replace(" ", "").strip().lower()
    if not s or (len(s) % 2) != 0:
        return False
    for c in s:
        if c not in "0123456789abcdef":
            return False
    return True

def _datatype_name(dt):
    name = dt.getDisplayName()
    if name:
        return name
    return dt.getName()

def _datatype_to_c_text(dt):
    writer = StringWriter()
    dt_writer = DataTypeWriter(currentProgram.getDataTypeManager(), writer)
    dt_list = LinkedList()
    dt_list.add(dt)
    dt_writer.write(dt_list, TaskMonitor.DUMMY)
    return writer.toString().strip()

def _find_datatype(ghidra, datatype_name):
    dt_list = LinkedList()
    ghidra.find_datatypes(datatype_name, dt_list)
    if dt_list.isEmpty():
        return None
    for dt in dt_list:
        if dt.getName() == datatype_name or dt.getDisplayName() == datatype_name:
            return dt
    return dt_list.get(0)

KINGAIDRA_MCP_NAME = "ghidra_mcp"
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
                "name": "get_callee_function",
                "description": "Retrieve functions that are called by the specified function and return their names and addresses.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {"type": "string"},
                    },
                    "required": ["func_name"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_caller_function",
                "description": "Retrieve functions that call the specified function and return their names and addresses.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {"type": "string"},
                    },
                    "required": ["func_name"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_asm_by_address",
                "description": "Retrieve the assembly code of the specified function. Address is hex string (e.g. 0x401000).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "hex string"},
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
                        "func_name": {"type": "string"},
                    },
                    "required": ["func_name"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_decompiled_code_by_address",
                "description": "Retrieve the decompiled code of the specified function in C language. Address is hex string (e.g. 0x401000).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "hex string"},
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
                        "func_name": {"type": "string"},
                    },
                    "required": ["func_name"],
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
                        "address": {"type": "string", "description": "hex string"},
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
                        "address": {"type": "string", "description": "hex string"},
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
                "name": "get_imports",
                "description": "Retrieve imported functions and their addresses.",
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
                "name": "get_exports",
                "description": "Retrieve exported functions and their addresses.",
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
                "description": "Returns a list of reference source addresses to the specified address. Address is hex string.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "hex string"},
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
                "name": "get_bytes",
                "description": "Get bytes at address and return a hexdump. Address is hex string, size is byte count.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "hex string"},
                        "size": {"type": "integer"}
                    },
                    "required": ["address", "size"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "search_asm",
                "description": "Search assembly by substring match with whitespace ignored. Use ';' or newline to separate multiple instructions (sequence search).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"}
                    },
                    "required": ["query"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "search_decom",
                "description": "Search decompiled C code by substring match with whitespace ignored. Searches all functions and can be slow.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"}
                    },
                    "required": ["query"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "run_script",
                "description": "Run a Ghidra script with fixed script filename. Provide script_code (full script text) and args (string list).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "script_code": {"type": "string"},
                        "args": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["script_code", "args"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "search_bytes",
                "description": "Search for a byte sequence in memory. bytes_hex is hex string, spaces allowed (e.g. '55 8B EC').",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "bytes_hex": {"type": "string"}
                    },
                    "required": ["bytes_hex"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_datatype",
                "description": "Retrieve a datatype definition in C syntax by datatype name.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "datatype_name": {"type": "string"}
                    },
                    "required": ["datatype_name"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
        {
            "type": "function",
            "function": {
                "name": "create_datatype_from_c_source",
                "description": "Create datatype(s) from C source text (Parse C Source style).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "c_source": {"type": "string"}
                    },
                    "required": ["c_source"],
                    "additionalProperties": False
                },
                "strict": True
            }
        },
    ]
    for tool in data["tools"]:
        func = tool.get("function")
        name = func.get("name")
        func["name"] = KINGAIDRA_MCP_NAME + "_" + name

def handle_tool_call(tool_call, ghidra):
    func_name = tool_call["function"]["name"][len(KINGAIDRA_MCP_NAME + "_"):]
    args = json.loads(tool_call["function"]["arguments"])
    content = ""
    if func_name == "get_current_address":
        content = "%#x" % (ghidra.get_current_addr().getOffset())
    elif func_name == "get_function_address_by_name":
        same_name_funcs = ghidra.get_func(args["name"])
        if not same_name_funcs:
            content = "None"
            return content
        content = "Addresses list.\n"
        for func in same_name_funcs:
            content += "- %x\n" % (func.getEntryPoint().getOffset())
    elif func_name == "get_function_list":
        func_itr = currentProgram.getListing().getFunctions(True)
        content = "Functions list.\n"
        while func_itr.hasNext():
            func = func_itr.next()
            content += "- [%#x]: %s\n" % (func.getEntryPoint().getOffset(), func.getName())
    elif func_name == "get_callee_function":
        func_list = ghidra.get_func(args["func_name"])
        if not len(func_list):
            content = "Invalid function name"
            return content
        content = ""
        for func in func_list:
            callee_func_list = ghidra.get_callee(func)
            content += "%s\n" % func.getName()
            for callee_func in callee_func_list:
                content += "- [%#x]: %s\n" % (callee_func.getEntryPoint().getOffset(), callee_func.getName())
            content += "\n"
    elif func_name == "get_caller_function":
        func_list = ghidra.get_func(args["func_name"])
        if not len(func_list):
            content = "Invalid function name"
            return content
        content = ""
        for func in func_list:
            caller_func_list = ghidra.get_caller(func)
            content += "%s\n" % func.getName()
            for caller_func in caller_func_list:
                content += "- [%#x]: %s\n" % (caller_func.getEntryPoint().getOffset(), caller_func.getName())
            content += "\n"
    elif func_name == "get_asm":
        same_name_funcs = ghidra.get_func(args["func_name"])
        if not len(same_name_funcs) == 1:
            content = "Failed"
            return content
        content = ""
        for func in same_name_funcs:
            content += ghidra.get_asm(func.getEntryPoint(), True) + "\n\n"
    elif func_name == "get_asm_by_address":
        try:
            addr = int(args["address"], 16)
        except ValueError:
            return "Invalid address format"
        content = ghidra.get_asm(ghidra.get_addr(addr))
        if not content:
            content = "Invalid address"
            return content
    elif func_name == "get_decompiled_code":
        same_name_funcs = ghidra.get_func(args["func_name"])
        if not len(same_name_funcs) == 1:
            content = "Failed"
            return content
        content = ""
        for func in same_name_funcs:
            content += ghidra.get_decom(func.getEntryPoint()) + "\n\n"
    elif func_name == "get_decompiled_code_by_address":
        try:
            addr = int(args["address"], 16)
        except ValueError:
            return "Invalid address format"
        content = ghidra.get_decom(ghidra.get_addr(addr))
        if not content:
            content = "Invalid address"
            return content
    elif func_name == "refactoring":
        try:
            addr = int(args["address"], 16)
        except ValueError:
            return "Invalid address format"
        diff = ghidra.get_decomdiff(ghidra.get_addr(addr))
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
        try:
            addr = int(args["address"], 16)
        except ValueError:
            return "Invalid address format"
        addr = ghidra.get_addr(addr)
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
            return content
        content = "Strings list.\n"
        for data in data_list:
            content += "- [%#x]: %s\n" % (data.getAddress().getOffset(), data.getDefaultValueRepresentation())
    elif func_name == "get_imports":
        fm = currentProgram.getFunctionManager()
        itr = fm.getExternalFunctions()
        content = "Imports list.\n"
        has_any = False
        while itr.hasNext():
            f = itr.next()
            name = f.getName()
            ns = f.getParentNamespace()
            if ns:
                content += "- %s (%s)\n" % (name, ns.getName())
            else:
                content += "- %s\n\n" % (name)
            has_any = True
        if not has_any:
            content = "None"
            return content
    elif func_name == "get_exports":
        symtab = currentProgram.getSymbolTable()
        itr = symtab.getExternalEntryPointIterator()
        content = "Exports list.\n"
        has_any = False
        while itr.hasNext():
            addr = itr.next()
            sym = symtab.getPrimarySymbol(addr)
            if sym is None:
                continue
            name = sym.getName()
            content += "- [%#x]: %s\n" % (addr.getOffset(), name)
            has_any = True
        if not has_any:
            content = "None"
            return content
    elif func_name == "get_ref_to":
        try:
            addr = int(args["address"], 16)
        except ValueError:
            return "Invalid address format"
        ref_list = ghidra.get_ref_to(ghidra.get_addr(addr))
        if not ref_list:
            content = "None"
            return content
        content = "Reference address.\n"
        for ref in ref_list:
            content += "- %#x\n" % (ref.getFromAddress().getOffset())
    elif func_name == "get_bytes":
        try:
            addr = int(args["address"], 16)
        except ValueError:
            return "Invalid address format"
        size = args.get("size", 1)
        if size <= 0:
            return "Size must be > 0"
        base = ghidra.get_addr(addr)
        buf = ghidra.get_bytes(base, size)
        if buf is None:
            content = "Error reading memory"
            return content
        content = _hexdump(base, buf)
    elif func_name == "search_bytes":
        bytes_hex = args.get("bytes_hex")
        if not _is_valid_hex_string(bytes_hex):
            return "Error: invalid hex"
        hits = ghidra.search_bytes(bytes_hex)
        if not hits:
            content = "None"
        else:
            content = "\n".join([str(a) for a in hits])
    elif func_name == "search_asm":
        query = args.get("query")
        if not query:
            return "Query is required"
        hits = ghidra.search_asm(query)
        if not hits:
            content = "None"
        else:
            lines = []
            listing = currentProgram.getListing()
            for addr in hits:
                inst = listing.getInstructionAt(addr)
                asm = inst.toString() if inst else "(no instruction)"
                lines.append("%s: %s" % (addr, asm))
            content = "\n".join(lines)
    elif func_name == "search_decom":
        query = args.get("query")
        if not query:
            return "Query is required"
        hits = ghidra.search_decom(query)
        if not hits:
            content = "None"
        else:
            lines = []
            for addr in hits:
                func = ghidra.get_func(addr)
                if func is not None:
                    lines.append("%s: %s" % (addr, func.getName()))
                else:
                    lines.append(str(addr))
            content = "\n".join(lines)
    elif func_name == "run_script":
        script_code = args.get("script_code")
        if script_code is None or script_code == "":
            return "script_code is required"
        script_args = args.get("args")
        if script_args is None:
            script_args = []
        try:
            result = ghidra.run_script(FIXED_SCRIPT_FILE, script_args, script_code)
            content = json.dumps({
                "success": result.get_success(),
                "stdout": result.get_stdout(),
                "stderr": result.get_stderr(),
            })
        except Exception as e:
            msg = str(e)
            content = "Error: " + msg if msg else "Failed"
    elif func_name == "get_datatype":
        dt = _find_datatype(ghidra, args["datatype_name"])
        if dt is None:
            content = "None"
        else:
            content = _datatype_to_c_text(dt)
    elif func_name == "create_datatype_from_c_source":
        c_source = args.get("c_source")
        if c_source is None or c_source.strip() == "":
            return "C source is required"
        dt = ghidra.parse_datatypes(c_source)
        if dt is None:
            return "Failed to parse C source"
        ghidra.add_datatype(dt)
        content = "Success: " + _datatype_name(dt)
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
        data["messages"][-1]["content"] += "\n\n" + POST_MSG

    fail_count = 0
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

        if fail_count < 5 and response["choices"][0]["finish_reason"] == "stop" and response["choices"][0]["message"]["content"] is None:
            fail_count += 1
            continue

        data["messages"].append(response["choices"][0]["message"])
        if response["choices"][0]["finish_reason"] == "tool_calls":
            for i in response["choices"][0]["message"]["tool_calls"]:
                try:
                    content = handle_tool_call(i, ghidra)
                except (Exception, JException) as e:
                    msg = str(e)
                    if msg:
                        content = "Error: " + msg
                    else:
                        content = "Error: " + e.__class__.__name__
                data["messages"].append({"role": "tool", "tool_call_id": i["id"], "content": content})
        elif response["choices"][0]["finish_reason"] == "stop":
            break
    result = response["choices"][0]["message"]["content"]

    state.addEnvironmentVar("RESPONSE", result)
    state.addEnvironmentVar("MESSAGES_OUT", json.dumps(data["messages"]))

if __name__ == "__main__":
    TOOLS_FLAG = globals().get("TOOLS_FLAG", True)
    main()
