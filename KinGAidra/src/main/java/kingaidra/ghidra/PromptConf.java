package kingaidra.ghidra;

import java.util.EnumMap;
import java.util.Map;

import ghidra.framework.options.Options;
import kingaidra.ai.task.TaskType;

public class PromptConf {
    public static final String OPTION_SYSTEM_PROMPT = "Prompt.System";
    public static final String OPTION_USER_PROMPT_PREFIX = "Prompt.User.";

    private static final String DEFAULT_SYSTEM_PROMPT = "You are a malware analysis expert.";

    private final Map<TaskType, String> default_user_prompts = new EnumMap<>(TaskType.class);
    private final Map<TaskType, String> user_prompt_overrides = new EnumMap<>(TaskType.class);
    private final Map<TaskType, String> system_prompt_overrides = new EnumMap<>(TaskType.class);

    private String system_prompt;
    private Options options;

    public PromptConf() {
        system_prompt = DEFAULT_SYSTEM_PROMPT; // "You are a senior reverse-engineer.";
        init_default_user_prompts();
    }

    public void bind_options(Options options) {
        this.options = options;
    }

    public static String get_user_prompt_option_name(TaskType task) {
        return OPTION_USER_PROMPT_PREFIX + task.name();
    }

    public String get_default_system_prompt_base() {
        return system_prompt;
    }

    public String get_default_system_prompt() {
        if (options == null) {
            return system_prompt;
        }
        return options.getString(OPTION_SYSTEM_PROMPT, system_prompt);
    }

    public void set_default_system_prompt(String data) {
        system_prompt = (data == null) ? "" : data;
        if (options != null) {
            options.setString(OPTION_SYSTEM_PROMPT, system_prompt);
        }
    }

    public String get_system_prompt(TaskType task, String model_name) {
        String override = system_prompt_overrides.get(task);
        return override == null ? get_default_system_prompt() : override;
    }

    public void set_system_prompt(TaskType task, String system_prompt) {
        if (system_prompt == null || system_prompt.isEmpty()) {
            system_prompt_overrides.remove(task);
        } else {
            system_prompt_overrides.put(task, system_prompt);
        }
    }

    public String get_default_user_prompt(TaskType task) {
        String prompt = default_user_prompts.get(task);
        return prompt == null ? "" : prompt;
    }

    public String get_user_prompt(TaskType task, String model_name) {
        String default_prompt = get_default_user_prompt(task);
        if (options != null) {
            return options.getString(get_user_prompt_option_name(task), default_prompt);
        }
        String override = user_prompt_overrides.get(task);
        return override == null ? default_prompt : override;
    }

    public void set_user_prompt(TaskType task, String model_name, String system_prompt) {
        if (options != null) {
            options.setString(get_user_prompt_option_name(task), system_prompt == null ? "" : system_prompt);
            return;
        }
        if (system_prompt == null || system_prompt.isEmpty()) {
            user_prompt_overrides.remove(task);
        } else {
            user_prompt_overrides.put(task, system_prompt);
        }
    }

    private void init_default_user_prompts() {
        default_user_prompts.put(TaskType.DECOM_REFACTOR_FUNC_PARAM_VAR,
                "Please improve the readability of the following code by renaming the functions, parameters, and variables with more descriptive and meaningful names. The new names should clearly reflect the purpose and behavior of the function and the role of every parameter and variable. Use snake_case for all function and variable names.\n" +
                "Since this function is processed in isolation and naming collisions may occur in a larger context, generate a function name that is uniquely descriptive based on what the function actually does. Include context clues in the name (e.g., related data, behavior, action performed) to help ensure uniqueness when aggregated with other renamed functions.\n" +
                "```\n" +
                "<code>\n" +
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
                "```");

        default_user_prompts.put(TaskType.REVIEW_DECOM_REFACTOR_FUNC_PARAM_VAR,
                "Please review the following refactoring proposal and determine if it should be applied.\n" +
                "- Is the refactoring result correct?\n" +
                "- Is the refactoring result useful for analysis?\n" +
                "Based on facts, please respond only using information that can be verified.\n" +
                "# Refactoring target\n" +
                "```\n" +
                "<code>\n" +
                "```\n" +
                "\n" +
                "# Refactoring Proposal\n" +
                "```\n" +
                "%s\n" +
                "```\n" +
                "\n" +
                "Output should absolutely be JSON only.\n" +
                "No additional explanation is needed.\n" +
                "The format is as follows.\n" +
                "```json\n" +
                "{\n" +
                "    \"detail\": \"Description of the refactoring proposal\",\n" +
                "    \"result\": true/false (Whether the refactoring proposal should be applied),\n" +
                "    \"confidence\": \"Confidence (0.0-1.0)\"\n" +
                "}\n" +
                "```");

        default_user_prompts.put(TaskType.DECOM_REFACTOR_DATATYPE,
                "I have decompiled C code that contains various data type issues due to the decompilation process. I need your help to review the code and make the necessary corrections to the data types. Please go over the code and make these adjustments to improve the accuracy of the data types.\n" +
                "```cpp\n" +
                "<code>\n" +
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
                "```");

        default_user_prompts.put(TaskType.REVIEW_DECOM_REFACTOR_DATATYPE,
                "Please review the following refactoring proposal and determine if it should be applied.\n" +
                "- Is the refactoring result correct?\n" +
                "- Is the refactoring result useful for analysis?\n" +
                "Based on facts, please respond only using information that can be verified.\n" +
                "# Refactoring target\n" +
                "```\n" +
                "<code>\n" +
                "```\n" +
                "\n" +
                "# Refactoring Proposal\n" +
                "```\n" +
                "%s\n" +
                "```\n" +
                "\n" +
                "Output should absolutely be JSON only.\n" +
                "No additional explanation is needed.\n" +
                "The format is as follows.\n" +
                "```json\n" +
                "{\n" +
                "    \"detail\": \"Description of the refactoring proposal\",\n" +
                "    \"result\": true/false (Whether the refactoring proposal should be applied),\n" +
                "    \"confidence\": \"Confidence (0.0-1.0)\"\n" +
                "}\n" +
                "```");

        default_user_prompts.put(TaskType.CHAT, "");

        default_user_prompts.put(TaskType.CHAT_EXPLAIN_DECOM,
                "Please explain what the following decompiled C function does. "
                + "Break down its logic, and describe the purpose of each part of the function, including any key operations, conditionals, loops, and data structures involved. "
                + "Providea step-by-step explanation of how the function works and what its expected behavior would be when executed.\n"
                + "```cpp\n" + "<code>\n" + "```");

        default_user_prompts.put(TaskType.CHAT_EXPLAIN_ASM,
                "Please explain what the following function does from its assembly listing. " +
                "Infer the calling convention, parameters, and return value; describe the stack frame and register usage; map the control flow (basic blocks, branches, loops); and highlight key instructions, memory reads/writes, constants, external calls, and side effects. Provide a concise step-by-step walkthrough (brief pseudocode if helpful) and end with a one-sentence summary of the function's purpose. Note any error paths or suspicious patterns.\n" +
                "```asm\n<asm>\n```");

        default_user_prompts.put(TaskType.CHAT_DECOM_ASM,
                "Decompile the following assembly code into equivalent C code.\n```asm\n<asm>\n```");

        default_user_prompts.put(TaskType.CHAT_EXPLAIN_STRINGS,
                "Given a list of strings found within a malware sample, identify and list the strings that might be useful for further analysis. Focus on strings that could provide insight into the malware's functionality, its command-and-control server, or its intentions. Prioritize strings related to:\n" +
                "\n" +
                "1. URLs or IP addresses - Potential command-and-control servers, communication endpoints, or external resources.\n" +
                "2. File paths or registry keys - Locations of potential artifacts, dropped files, or persistence mechanisms.\n" +
                "3. Function names or API calls - Indications of specific malware behaviors or techniques.\n" +
                "4. Encryption keys or sensitive data - Possible use of cryptography, encoding, or sensitive information handling.\n" +
                "5. Error messages or logs - Clues to how the malware operates, crashes, or logs activity.\n" +
                "6. Hardcoded credentials or authentication tokens - Useful for identifying compromised access methods.\n" +
                "7. Strings associated with known malware families or threat actor tactics - Help in associating the sample with a specific threat group or malware variant.\n" +
                "\n" +
                "Filter out irrelevant or common strings such as system files, non-specific text, or internal programming strings. Focus on identifying strings that could reveal malicious actions or associations.\n" +
                "All strings in the output must be wrapped in backticks (`).\n" +
                "\n" +
                "Strings:\n" +
                "<strings>");

        default_user_prompts.put(TaskType.ADD_COMMENTS,
                "Please add comments to the following C language function to explain its purpose and logic. The comments should be concise but clear, and should describe the function, parameters, logic, and any important details for each part of the code. Return the results in the following format:\n" +
                "\n" +
                "```json\n" +
                "[\n" +
                "    {\n" +
                "        \"source\": \"source code line A\",\n" +
                "        \"comment\": \"comment A\"\n" +
                "    },\n" +
                "    {\n" +
                "        \"source\": \"source code line B\",\n" +
                "        \"comment\": \"comment B\"\n" +
                "    },\n" +
                "    ...\n" +
                "]\n" +
                "```\n" +
                "\n" +
                "Here is the C code:\n" +
                "\n" +
                "```cpp\n" +
                "<code>\n" +
                "```");

        default_user_prompts.put(TaskType.DECOM_RESOLVE_DATATYPE, "");
        default_user_prompts.put(TaskType.KEYFUNC_CALLTREE, "");
    }
}
