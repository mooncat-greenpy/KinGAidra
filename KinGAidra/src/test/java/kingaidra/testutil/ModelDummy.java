package kingaidra.testutil;

import java.io.Serializable;

import ghidra.app.script.GhidraState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.decom.DecomDiff;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelType;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.ai.task.TaskType;

public class ModelDummy implements Model, Serializable {
    String name;
    String script_file;
    boolean active;
    ModelType type;
    DecomDiff data;

    public ModelDummy(String name, String script, boolean active) {
        this.name = name;
        this.script_file = script;
        this.active = active;
        this.type = ModelType.CHAT;
    }

    public String get_name() {
        return name;
    }

    public void set_name(String name) {
        this.name = name;
    }

    public String get_script() {
        return script_file;
    }

    public void set_script(String script_file) {
        this.script_file = script_file;
    }

    public boolean get_active() {
        return active;
    }

    public void set_active(boolean b) {
        this.active = b;
    }

    public ModelType get_type() {
        return type;
    }

    public void set_type(ModelType type) {
        this.type = type;
    }

    public Conversation guess(TaskType task_type, Conversation convo, KinGAidraChatTaskService service, PluginTool tool,
            Program program, GhidraState src_state) {
        if (task_type == TaskType.DECOM_REFACTOR_FUNC_PARAM_VAR && convo.get_msg(convo.get_msgs_len() - 1).contains("func_401000") && convo.get_msg(convo.get_msgs_len() - 1).contains("new_func_name")) {
            convo.add_assistant_msg("{\n" +
                        "    \"new_func_name\": \"func_401000" + name + "\",\n" +
                        "    \"orig_func_name\": \"func_401000\",\n" +
                        "    \"parameters\": [\n" +
                        "    ],\n" +
                        "    \"variables\": [\n" +
                        "        {\n" +
                        "            \"new_var_name\": \"in_EAX" + name + "\",\n" +
                        "            \"orig_var_name\": \"in_EAX\"\n" +
                        "        }\n" +
                        "    ]\n" +
                        "}");
        } else if (task_type == TaskType.DECOM_REFACTOR_FUNC_PARAM_VAR && convo.get_msg(convo.get_msgs_len() - 1).contains("func_402000") && convo.get_msg(convo.get_msgs_len() - 1).contains("new_func_name")) {
            convo.add_assistant_msg("{\n" +
                        "    \"new_func_name\": \"func_402000" + name + "\",\n" +
                        "    \"orig_func_name\": \"func_402000\",\n" +
                        "    \"parameters\": [\n" +
                        "        {\n" +
                        "            \"new_param_name\": \"param_1" + name + "\",\n" +
                        "            \"orig_param_name\": \"param_1\"\n" +
                        "        }\n" +
                        "    ],\n" +
                        "    \"variables\": [\n" +
                        "        {\n" +
                        "            \"new_var_name\": \"piVar1" + name + "\",\n" +
                        "            \"orig_var_name\": \"piVar1\"\n" +
                        "        },\n" +
                        "        {\n" +
                        "            \"new_var_name\": \"in_EAX" + name + "\",\n" +
                        "            \"orig_var_name\": \"in_EAX\"\n" +
                        "        },\n" +
                        "        {\n" +
                        "            \"new_var_name\": \"puVar2" + name + "\",\n" +
                        "            \"orig_var_name\": \"puVar2\"\n" +
                        "        },\n" +
                        "        {\n" +
                        "            \"new_var_name\": \"in_EDX" + name + "\",\n" +
                        "            \"orig_var_name\": \"in_EDX\"\n" +
                        "        },\n" +
                        "        {\n" +
                        "            \"new_var_name\": \"unaff_EBX" + name + "\",\n" +
                        "            \"orig_var_name\": \"unaff_EBX\"\n" +
                        "        },\n" +
                        "        {\n" +
                        "            \"new_var_name\": \"unaff_EDI" + name + "\",\n" +
                        "            \"orig_var_name\": \"unaff_EDI\"\n" +
                        "        },\n" +
                        "        {\n" +
                        "            \"new_var_name\": \"in_stack_00000004" + name + "\",\n" +
                        "            \"orig_var_name\": \"in_stack_00000004\"\n" +
                        "        }\n" +
                        "    ]\n" +
                        "}");
        } else if (task_type == TaskType.DECOM_REFACTOR_DATATYPE && convo.get_msg(convo.get_msgs_len() - 1).contains("func_401000") && convo.get_msg(convo.get_msgs_len() - 1).contains("new_datatype")) {
            convo.add_assistant_msg("[\n" +
                                "    {\n" +
                                "        \"new_datatype\": \"int" + name + "\",\n" +
                                "        \"orig_datatype\": \"int\",\n" +
                                "        \"var_name\": \"in_EAX\"\n" +
                                "    }\n" +
                                "]");
        } else if (task_type == TaskType.DECOM_REFACTOR_DATATYPE && convo.get_msg(convo.get_msgs_len() - 1).contains("func_402000") && convo.get_msg(convo.get_msgs_len() - 1).contains("new_datatype")) {
            convo.add_assistant_msg("[\n" +
                                "    {\n" +
                                "        \"new_datatype\": \"pointer" + name + "\",\n" +
                                "        \"orig_datatype\": \"pointer\",\n" +
                                "        \"var_name\": \"param_1\"\n" +
                                "    },\n" +
                                "    {\n" +
                                "        \"new_datatype\": \"int*" + name + "\",\n" +
                                "        \"orig_datatype\": \"int*\",\n" +
                                "        \"var_name\": \"piVar1\"\n" +
                                "    },\n" +
                                "    {\n" +
                                "        \"new_datatype\": \"char*" + name + "\",\n" +
                                "        \"orig_datatype\": \"char*\",\n" +
                                "        \"var_name\": \"in_EAX\"\n" +
                                "    },\n" +
                                "    {\n" +
                                "        \"new_datatype\": \"undefined4*" + name + "\",\n" +
                                "        \"orig_datatype\": \"undefined4*\",\n" +
                                "        \"var_name\": \"puVar2\"\n" +
                                "    },\n" +
                                "    {\n" +
                                "        \"new_datatype\": \"int" + name + "\",\n" +
                                "        \"orig_datatype\": \"int\",\n" +
                                "        \"var_name\": \"in_EDX\"\n" +
                                "    },\n" +
                                "    {\n" +
                                "        \"new_datatype\": \"int" + name + "\",\n" +
                                "        \"orig_datatype\": \"int\",\n" +
                                "        \"var_name\": \"unaff_EBX\"\n" +
                                "    },\n" +
                                "    {\n" +
                                "        \"new_datatype\": \"int" + name + "\",\n" +
                                "        \"orig_datatype\": \"int\",\n" +
                                "        \"var_name\": \"unaff_EDI\"\n" +
                                "    },\n" +
                                "    {\n" +
                                "        \"new_datatype\": \"undefined4*" + name + "\",\n" +
                                "        \"orig_datatype\": \"undefined4*\",\n" +
                                "        \"var_name\": \"in_stack_00000004\"\n" +
                                "    }\n" +
                                "]");
        } else if (task_type == TaskType.DECOM_RESOLVE_DATATYPE && convo.get_msg(convo.get_msgs_len() - 1).contains(" PROCESSENTRY32W.")) {
            convo.add_assistant_msg("Here is the PROCESSENTRY32W structure in C language, along with its dependent data types and structures, for 32-bit systems:\n" +
                                "```\n" +
                                "typedef wchar_t WCHAR;\n" +
                                "typedef unsigned long ULONG_PTR;\n" +
                                "typedef unsigned long DWORD;\n" +
                                "typedef int BOOL;\n" +
                                "typedef unsigned short WORD;\n" +
                                "typedef unsigned long ULONG;\n" +
                                "typedef long LONG;\n" +
                                "\n" +
                                "typedef struct _FILETIME {\n" +
                                "    DWORD dwLowDateTime;\n" +
                                "    DWORD dwHighDateTime;\n" +
                                "} FILETIME;\n" +
                                "\n" +
                                "typedef struct _PROCESSENTRY32W {\n" +
                                "    DWORD dwSize;\n" +
                                "    DWORD cntUsage;\n" +
                                "    DWORD th32ProcessID;\n" +
                                "    ULONG_PTR th32DefaultHeapID;\n" +
                                "    DWORD th32ModuleID;\n" +
                                "    DWORD cntThreads;\n" +
                                "    DWORD th32ParentProcessID;\n" +
                                "    LONG pcPriClassBase;\n" +
                                "    DWORD dwFlags;\n" +
                                "    WCHAR szExeFile[260]; // MAX_PATH\n" +
                                "} PROCESSENTRY32W;\n" +
                                "```\n" +
                                "Note that `ULONG_PTR` is a pointer to an unsigned long integer, which is a 32-bit value on 32-bit systems. On 64-bit systems, it would be a pointer to an unsigned long long integer.\n" +
                                "\n" +
                                "Also, `WCHAR` is a wide character type, which is a 16-bit Unicode character on Windows.\n" +
                                "");
        } else if (task_type == TaskType.DECOM_RESOLVE_DATATYPE && convo.get_msg(convo.get_msgs_len() - 1).contains(" PROCESSENTRY32.")) {
            convo.add_assistant_msg("Here is the `PROCESSENTRY32` structure written in C for a 32-bit environment, including any necessary dependent data types and structures:\n" +
                                "\n" +
                                "```c\n" +
                                "typedef unsigned long DWORD;\n" +
                                "typedef unsigned long ULONG_PTR;\n" +
                                "typedef char TCHAR;\n" +
                                "typedef unsigned short WORD;\n" +
                                "typedef unsigned long ULONG;\n" +
                                "\n" +
                                "typedef struct _PROCESSENTRY32 {\n" +
                                "    DWORD dwSize;              // Size of the structure in bytes\n" +
                                "    DWORD cntUsage;            // Count of the number of times the process has been used\n" +
                                "    DWORD th32ProcessID;       // Process ID\n" +
                                "    ULONG_PTR th32DefaultHeapID; // Default heap ID\n" +
                                "    DWORD th32ModuleID;        // Module ID\n" +
                                "    DWORD cntThreads;          // Handle to the process\n" +
                                "    DWORD th32ParentProcessID; // Parent process ID\n" +
                                "    DWORD dwPriorityClass;     // Priority class of the process\n" +
                                "    DWORD dwFlags;             // Flags related to the process\n" +
                                "    TCHAR szExeFile[MAX_PATH]; // Path of the executable file for the process\n" +
                                "} PROCESSENTRY32;\n" +
                                "\n" +
                                "// Maximum length of the executable file path\n" +
                                "#define MAX_PATH 260\n" +
                                "```\n" +
                                "\n" +
                                "### Breakdown of the structure:\n" +
                                "1. **`dwSize`**: Specifies the size of the structure, which is used for versioning.\n" +
                                "2. **`cntUsage`**: A count of how many times the process has been used (although not typically used in modern API calls).\n" +
                                "3. **`th32ProcessID`**: The process ID of the target process.\n" +
                                "4. **`th32DefaultHeapID`**: The default heap ID for the process, typically used in older Windows APIs.\n" +
                                "5. **`th32ModuleID`**: Module ID of the process (often not used in current Windows versions).\n" +
                                "6. **`hProcess`**: A handle to the process.\n" +
                                "7. **`th32ParentProcessID`**: The parent process ID.\n" +
                                "8. **`dwPriorityClass`**: The priority class for the process (like normal, high, etc.).\n" +
                                "9. **`dwFlags`**: Flags indicating various process attributes.\n" +
                                "10. **`szExeFile`**: The executable file's full path.\n" +
                                "\n" +
                                "Additionally, I defined **`MAX_PATH`** as `260`, which is the typical maximum length of file paths in Windows.");
        } else if (task_type == TaskType.KEYFUNC_CALLTREE && convo.get_msg(convo.get_msgs_len() - 1).contains("please list which functions")) {
            convo.add_assistant_msg("```json\n" +
                        "{\n" +
                        "    \"func\": [\n" +
                        "        \"func_401000\",\n" +
                        "        \"func_404000\",\n" +
                        "        \"func_406000\"\n" +
                        "    ]\n" +
                        "}\n" +
                        "```");
        } else if (task_type == TaskType.KEYFUNC_STRING && convo.get_msg(convo.get_msgs_len() - 1).contains("strings")) {
            convo.add_assistant_msg("```json\n" +
                        "{\n" +
                        "    \"func\": [\n" +
                        "        \"Func_1\",\n" +
                        "        \"Func_2\",\n" +
                        "        \"Func_3\"\n" +
                        "    ]\n" +
                        "}\n" +
                        "```" +
                        "- `string1`\n" +
                        "- `string2`, `string3`" +
                        "test\n" +
                        "test`ing2`test\n" +
                        "```cpp\n" +
                        "test\n" +
                        "```");
        } else if (task_type == TaskType.ADD_COMMENTS) {
            convo.add_assistant_msg("```json\n" +
                        "[\n" +
                        "    {\n" +
                        "        \"source\": \"piVar1 = (int *)(unaff_EBX + -0x3f7bfe3f);\",\n" +
                        "        \"comment\": \"comment1\"\n" +
                        "    },\n" +
                        "    {\n" +
                        "        \"source\": \"do {\",\n" +
                        "        \"comment\": \"comment2\"\n" +
                        "    },\n" +
                        "    {\n" +
                        "        \"source\": \"return ((uint)in_EAX & 0xffffff04) - (int)in_stack_00000004;\",\n" +
                        "        \"comment\": \"comment3\"\n" +
                        "    },\n" +
                        "    {\n" +
                        "        \"source\": \"return (int)in_EAX - (int)in_stack_00000004;\",\n" +
                        "        \"comment\": \"comment4\"\n" +
                        "    }\n" +
                        "]\n" +
                        "```");
        }

        return convo;
    }
}
