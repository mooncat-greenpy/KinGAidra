package kingaidra.decom.ai;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.decom.DecomDiff;
import kingaidra.chat.KinGAidraChatTaskService;
import kingaidra.ai.TaskType;
import kingaidra.chat.Conversation;

public class Ai {
    private PluginTool tool;
    private Program program;
    private KinGAidraChatTaskService service;

    public Ai(PluginTool tool, Program program, KinGAidraChatTaskService service) {
        this.tool = tool;
        this.program = program;
        this.service = service;
    }

    public DecomDiff guess(DecomDiff diff) {
        if (!guess_func_param_var(diff)) {
            return null;
        }

        if (!guess_datatype(diff)) {
            return diff;
        }

        return diff;
    }

    private boolean guess_func_param_var(DecomDiff diff) {
        Conversation convo = new Conversation(diff.get_model());
        if (!convo.add_user_msg(String.format("Please improve the readability of the following code by renaming the functions, parameters, and variables with more descriptive and meaningful names. The new names should better reflect the purpose of the functions and the role of each variable in the code.\n" +
                        "```\n" +
                        "%s\n" +
                        "```\n" +
                        "Output should absolutely be JSON only.\n" +
                        "No additional explanation is needed.\n" +
                        "The format is as follows.\n" +
                        "```json\n" +
                        "{\n" +
                        "    \"new_func_name\": \"new function name\",\n" +
                        "    \"orig_func_name\": \"original function name\",\n" +
                        "    \"parameters\": [\n" +
                        "        {\n" +
                        "            \"new_param_name\": \"new parameter name\",\n" +
                        "            \"orig_param_name\": \"original parameter name\"\n" +
                        "        },\n" +
                        "    ],\n" +
                        "    \"variables\": [\n" +
                        "        {\n" +
                        "            \"new_var_name\": \"new variable name\",\n" +
                        "            \"orig_var_name\": \"original variable name\"\n" +
                        "        }\n" +
                        "    ]\n" +
                        "}\n" +
                        "```", diff.get_src_code()))) {
            return false;
        }
        convo = diff.get_model().guess(TaskType.DECOM_REFACTOR_FUNC_PARAM_VAR, convo, service, tool, program);
        if (convo == null) {
            return false;
        }
        JsonExtractor<FuncParamVarJson> extractor = new JsonExtractor<>(convo.get_msg(convo.get_msgs_len() - 1), FuncParamVarJson.class);
        FuncParamVarJson func_json = extractor.get_data();
        if (func_json == null) {
            return false;
        }
        diff.set_name(func_json.get_new_func_name());
        for (ParamJson param : func_json.get_parameters()) {
            diff.set_param_new_name(param.get_orig_param_name(), param.get_new_param_name());
        }
        for (VarJson var : func_json.get_variables()) {
            diff.set_var_new_name(var.get_orig_var_name(), var.get_new_var_name());
        }
        return true;
    }

    private boolean guess_datatype(DecomDiff diff) {
        Conversation convo = new Conversation(diff.get_model());
        if (!convo.add_user_msg(String.format("I have decompiled C code that contains various data type issues due to the decompilation process. I need your help to review the code and make the necessary corrections to the data types. Please go over the code and make these adjustments to improve the accuracy of the data types.\n" +
                        "```cpp\n" +
                        "%s\n" +
                        "```\n" +
                        "The changes should be output in JSON format.\n" +
                        "```json\n" +
                        "[\n" +
                        "    {\n" +
                        "        \"new_datatype\": \"new datatype name\",\n" +
                        "        \"orig_datatype\": \"original datatype name\",\n" +
                        "        \"var_name\": \"variable name\"\n" +
                        "    },\n" +
                        "    ...\n" +
                        "]\n" +
                        "```", diff.get_src_code()))) {
            return false;
        }
        convo = diff.get_model().guess(TaskType.DECOM_REFACTOR_DATATYPE, convo, service, tool, program);
        if (convo == null) {
            return false;
        }
        JsonExtractor<DataTypeListJson> extractor = new JsonExtractor<>(convo.get_msg(convo.get_msgs_len() - 1), DataTypeListJson.class);
        DataTypeListJson datatype_json = extractor.get_data();
        if (datatype_json == null) {
            return false;
        }
        for (DataTypeJson param : datatype_json) {
            diff.set_datatype_new_name(param.get_var_name(), param.get_new_datatype());
        }

        return true;
    }
}
