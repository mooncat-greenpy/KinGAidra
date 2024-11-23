package kingaidra.testutil;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.DiffPair;
import kingaidra.chat.Conversation;
import kingaidra.chat.KinGAidraChatTaskService;
import kingaidra.chat.ai.Model;
import kingaidra.decom.ai.ModelType;

public class ModelDummy implements Model {
    String name;
    String script_file;
    boolean active;
    ModelType type;
    DecomDiff data;

    public ModelDummy(String name, String script, boolean active) {
        this.name = name;
        this.script_file = script;
        this.active = active;
        this.type = ModelType.DECOM_REFACTOR;
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

    public Conversation guess(Conversation convo, KinGAidraChatTaskService service, PluginTool tool,
            Program program) {
        if (convo.get_msg(convo.get_msgs_len() - 1).contains("func_401000") && convo.get_msg(convo.get_msgs_len() - 1).contains("new_func_name")) {
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
        } else if (convo.get_msg(convo.get_msgs_len() - 1).contains("func_402000") && convo.get_msg(convo.get_msgs_len() - 1).contains("new_func_name")) {
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
        } else if (convo.get_msg(convo.get_msgs_len() - 1).contains("func_401000") && convo.get_msg(convo.get_msgs_len() - 1).contains("new_datatype")) {
            convo.add_assistant_msg("[\n" +
                                "    {\n" +
                                "        \"new_datatype\": \"int" + name + "\",\n" +
                                "        \"orig_datatype\": \"int\",\n" +
                                "        \"var_name\": \"in_EAX\"\n" +
                                "    }\n" +
                                "]");
        } else if (convo.get_msg(convo.get_msgs_len() - 1).contains("func_402000") && convo.get_msg(convo.get_msgs_len() - 1).contains("new_datatype")) {
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
        }

        return convo;
    }
}
