//@author mooncat-greenpy
//@category KinGAidra
//@keybinding 
//@menupath 
//@toolbar 


import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.HashSet;
import java.util.List;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerGhidraProgram;
import kingaidra.ai.model.ModelConfSingle;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.ai.task.TaskType;
import kingaidra.decom.DecomDiff;
import kingaidra.ghidra.ChatModelPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.ghidra.PromptConf;


public class kingaidra_auto extends GhidraScript {

    private static final int DEFAULT_INTERVAL_MILLISECOND = 1000;
    private static final boolean DEFAULT_ALL_FUNC = false;
    private static final int DEFAULT_CALLED_RECURSIVE_COUNT = 4;
    private static final int DEFAULT_CALLING_RECURSIVE_COUNT = 4;
    private static final int DEFAULT_FUNCTION_COUNT_THRESHOLD = 1000;
    private static final boolean DEFAULT_ENABLE_REFACTOR = true;
    private static final boolean DEFAULT_ENABLE_ADD_COMMENTS = false;
    private static final boolean DEFAULT_ENABLE_REPORT = false;

    private static final int MAX_PROMPT_LINE = 3000;
    private static final String DEFAULT_REPORT_NAME = "report.md";

    private int interval_millisecond = DEFAULT_INTERVAL_MILLISECOND;
    private boolean all_func = DEFAULT_ALL_FUNC;
    private int called_recursive_count = DEFAULT_CALLED_RECURSIVE_COUNT;
    private int calling_recursive_count = DEFAULT_CALLING_RECURSIVE_COUNT;
    private int function_count_threshold = DEFAULT_FUNCTION_COUNT_THRESHOLD;
    private boolean enable_refactor = DEFAULT_ENABLE_REFACTOR;
    private boolean enable_add_comments = DEFAULT_ENABLE_ADD_COMMENTS;
    private boolean enable_report = DEFAULT_ENABLE_REPORT;
    private String report_name = DEFAULT_REPORT_NAME;

    private GhidraUtil ghidra;
    private kingaidra.chat.Guess chat_guess;
    private kingaidra.decom.Guess decom_guess;
    private kingaidra.decom.Refactor refactor;
    private kingaidra.keyfunc.Guess keyfunc_guess;

    private boolean verbose = false;

    private boolean refactoring(Function func) {
        try {
            DecomDiff[] diff_arr = decom_guess.guess_selected(func.getEntryPoint(), true);
            if (diff_arr.length < 1) {
                return false;
            }
            refactor.refact(diff_arr[0], false);
        } catch(Exception e) {
            return false;
        }
        return true;
    }

    private boolean add_comments(Function func) {
        try {
            List<Map.Entry<String, String>> comments = chat_guess.guess_src_code_comments(func.getEntryPoint());
            if (comments.size() < 1) {
                return false;
            }
            ghidra.add_comments(func.getEntryPoint(), comments);
        } catch(Exception e) {
            return false;
        }
        return true;
    }

    private void analyze_func(Function func) throws Exception {
        if (enable_refactor) {
            if (!refactoring(func)) {
                Thread.sleep(interval_millisecond);
                if (!refactoring(func)) {
                    return;
                }
            }
        }

        Thread.sleep(interval_millisecond);

        if (enable_add_comments) {
            ghidra.clear_comments(func.getEntryPoint());
            if (!add_comments(func)) {
                Thread.sleep(interval_millisecond);
                if (!add_comments(func)) {
                    return;
                }
            }
        }

        Thread.sleep(interval_millisecond);
    }

    public void add_func(List<Function> analyze_func_list, Function target) throws Exception {
        if (target.isExternal()) {
            return;
        }
        if (analyze_func_list.contains(target)) {
            return;
        }
        if (!target.getName().contains("FUN_")) {
            return;
        }
        analyze_func_list.add(target);
    }

    public void add_called_func_recur(List<Function> analyze_func_list, Function target, int recur_count) throws Exception {
        if (recur_count <= 0) {
            return;
        }
        for (Function called_func : target.getCalledFunctions(TaskMonitor.DUMMY)) {
            add_called_func_recur(analyze_func_list, called_func, recur_count - 1);
            add_func(analyze_func_list, called_func);
        }
    }

    public void add_calling_func_recur(List<Function> analyze_func_list, Function target, int recur_count) throws Exception {
        if (recur_count <= 0) {
            return;
        }
        for (Function calling_func : target.getCallingFunctions(TaskMonitor.DUMMY)) {
            add_called_func_recur(analyze_func_list, calling_func, called_recursive_count);
            add_func(analyze_func_list, calling_func);
            add_calling_func_recur(analyze_func_list, calling_func, recur_count - 1);
        }
    }

    private void summarize_report_funcs(List<String> report_list) {
        String prompt =
            "You are analyzing a malware sample using summaries from multiple function chunks.\n" +
            "\n" +
            "Please synthesize these summaries and generate a full **Markdown-formatted malware analysis report**, following this structure:\n" +
            "\n" +
            "---\n" +
            "\n" +
            "# Malware Analysis Report\n" +
            "\n" +
            "## 1. Executive Summary\n" +
            "Summarize the malware's purpose and behavior at a high level.\n" +
            "\n" +
            "## 2. Detailed Functional Analysis\n" +
            "For each functionality category, provide:\n" +
            "- A short description\n" +
            "- The names and addresses of functions that implement it\n" +
            "\n" +
            "### Encryption\n" +
            "- Description: ...\n" +
            "- Functions:\n" +
            "    - `<function_name>` (`<function_address>`): <description>\n" +
            "    - ...\n" +
            "\n" +
            "### C2 Communication\n" +
            "- Description: ...\n" +
            "- Functions:\n" +
            "    - `<function_name>` (`<function_address>`): <description>\n" +
            "    - ...\n" +
            "\n" +
            "... (repeat for other categories)\n" +
            "\n" +
            "## 3. APIs or Strings Found (if available)\n" +
            "List notable Windows APIs, URLs, registry keys, etc.\n" +
            "\n" +
            "## 4. Conclusion\n" +
            "State your judgment about the malware type (e.g., ransomware, RAT, info-stealer) and any recommendations or insights for malware analysts.\n" +
            "\n" +
            "---\n" +
            "\n" +
            "Below are the summaries from each chunk:\n" +
            "\n";

        for (int i = 0; i < report_list.size(); i++) {
            prompt += String.format("## chunk%d\n\n%s\n\n", i, report_list.get(i));
        }
        Conversation convo = chat_guess.guess(TaskType.CHAT, prompt, null);
        if (convo == null) {
            return;
        }
        String msg = convo.get_msg(convo.get_msgs_len() - 1);
        create_file(currentProgram.getName() + "_" + report_name, msg);
    }

    private String report_funcs(Function func, String report_prompt, List<String> report_list, boolean run_request) {
        String decom_str = ghidra.get_decom(func.getEntryPoint());
        if (decom_str == null) {
            return report_prompt;
        }
        report_prompt += String.format("# Address %s\n\n```cpp\n%s\n```\n\n", func.getEntryPoint(), decom_str).replace("KAI: ", "");
        if (report_prompt.split("\\R").length > MAX_PROMPT_LINE || run_request) {
            Conversation convo = chat_guess.guess(
                TaskType.CHAT,
                "You are analyzing a group of decompiled functions from a piece of malware.\n" +
                "\n" +
                "Please examine the code and generate a structured analysis in **Markdown format**, following these instructions:\n" +
                "\n" +
                "---\n" +
                "\n" +
                "### Instructions:\n" +
                "\n" +
                "1. Identify any of the following categories of functionality (you may add more if applicable):\n" +
                "   - C2 Communication\n" +
                "   - Persistence\n" +
                "   - Encryption\n" +
                "   - Information Gathering\n" +
                "   - File Operations\n" +
                "   - Process Manipulation\n" +
                "   - Anti-Analysis\n" +
                "   - Others (freely add if needed)\n" +
                "\n" +
                "2. For each category, explain the observed behavior and list the corresponding function names and addresses.\n" +
                "\n" +
                "3. Format your output in the following **Markdown structure** for malware analysts:\n" +
                "\n" +
                "---\n" +
                "\n" +
                "## Functionality Classification\n" +
                "\n" +
                "### C2 Communication\n" +
                "- **Description**: Brief explanation...\n" +
                "- **Functions**:\n" +
                "    - `<function_name>` (`<function_address>`): <description>\n" +
                "    - ...\n" +
                "\n" +
                "### Encryption\n" +
                "- **Description**: ...\n" +
                "- **Functions**:\n" +
                "    - `<function_name>` (`<function_address>`): <description>\n" +
                "    - ...\n" +
                "\n" +
                "... (repeat for other categories)\n" +
                "\n" +
                "---\n" +
                "\n" +
                "If possible, also mention any relevant APIs or strings found in the code (e.g., `InternetConnectA`, `CryptEncrypt`, `RegSetValueEx`).\n" +
                "\n" +
                "Below is the list of decompiled functions:\n" +
                "\n" +
                report_prompt
            , null);
            if (convo == null) {
                return report_prompt;
            }
            String msg = convo.get_msg(convo.get_msgs_len() - 1);
            report_list.add(msg);
            report_prompt = "";
        }
        return report_prompt;
    }

    private void create_file(String file_name, String data) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file_name, false))) {
            writer.write(data);
            writer.newLine();
        } catch (Exception e) {
        }
    }

    private void parse_args() {
        String[] args = getScriptArgs();

        for (int i = 0; i < args.length; i++) {
            String key = args[i];

            if (key.equals("-v")) {
                verbose = true;
                continue;
            }

            if (key.equals("-a")) {
                all_func = true;
                continue;
            }

            if (i + 1 >= args.length) {
                continue;
            }

            String value = args[i + 1];

            try {
                switch (key) {
                    case "interval":
                        interval_millisecond = Integer.parseInt(value);
                        break;
                    case "called_recur":
                        called_recursive_count = Integer.parseInt(value);
                        break;
                    case "calling_recur":
                        calling_recursive_count = Integer.parseInt(value);
                        break;
                    case "func_threshold":
                        function_count_threshold = Integer.parseInt(value);
                        break;
                    case "report_name":
                        report_name = value;
                        break;
                }
            } catch (NumberFormatException e) {
                println("Invalid number format for argument: " + key + " with value: " + value);
            }
        }

        if (verbose) {
            println(String.format("interval=%s", interval_millisecond));
            println(String.format("called_recur=%s", called_recursive_count));
            println(String.format("calling_recur=%s", calling_recursive_count));
            println(String.format("func_threshold=%s", function_count_threshold));
            println(String.format("report_name=%s", report_name));
        }
    }

    private List<Function> list_analyze_function_from_str() throws Exception {
        List<Function> analyze_func_list = new LinkedList();

        Data[] str_data_list = keyfunc_guess.guess_string_data();
        for (Data data : str_data_list) {
            Address addr = data.getAddress();
            String value = data.getDefaultValueRepresentation();
            List<Reference> refs = ghidra.get_ref_to(addr);
            if (refs == null || refs.size() == 0) {
                continue;
            }
            Set<Address> from_addr_set = new HashSet<>();
            for (Reference ref : refs) {
                from_addr_set.add(ref.getFromAddress());
            }
            for (Address from_addr : from_addr_set) {
                Function func = ghidra.get_func(from_addr);
                if (func == null) {
                    continue;
                }

                add_called_func_recur(analyze_func_list, func, called_recursive_count);

                add_func(analyze_func_list, func);

                add_calling_func_recur(analyze_func_list, func, calling_recursive_count);
            }
        }
        return analyze_func_list;
    }

    private List<Function> list_all_analyze_function() throws Exception {
        List<Function> analyze_func_list = new LinkedList();
        FunctionIterator itr = currentProgram.getListing().getFunctions(true);
        while (itr.hasNext()) {
            Function func = itr.next();
            add_called_func_recur(analyze_func_list, func, called_recursive_count);
            add_func(analyze_func_list, func);
        }
        return analyze_func_list;
    }

    private boolean analyze_function_auto() throws Exception {
        List<Function> analyze_func_list;
        if (all_func) {
            analyze_func_list = list_all_analyze_function();
        } else {
            analyze_func_list = list_analyze_function_from_str();
        }

        println(String.format("functions: %d", analyze_func_list.size()));
        if (analyze_func_list.size() > function_count_threshold) {
            println("Function count exceeds threshold, stopping analysis.");
            return false;
        }
        for (int i = 0; i < analyze_func_list.size(); i++) {
            monitor.checkCancelled();
            Function func = analyze_func_list.get(i);
            println("Refactoring: " + func.getName() + String.format(" (%d/%d)", i + 1, analyze_func_list.size()));
            analyze_func(func);
        }
        return true;
    }

    private boolean report_function_auto() throws Exception {
        if (!enable_report) {
            return false;
        }
        String report_prompt = "";
        List<String> report_list = new LinkedList<>();
        FunctionIterator itr = currentProgram.getListing().getFunctions(true);
        while (itr.hasNext()) {
            monitor.checkCancelled();
            report_prompt = report_funcs(itr.next(), report_prompt, report_list, !itr.hasNext());
        }
        summarize_report_funcs(report_list);
        return true;
    }

    public void run() throws Exception {
        parse_args();

        KinGAidraChatTaskService srv = null;
        PluginTool tool = state.getTool();
        ghidra = new GhidraUtilImpl(currentProgram, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerGhidraProgram(currentProgram, ghidra);
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(tool, currentProgram, ghidra, container, srv, conf);
        ai.set_ghidra_state(state);
        ModelConfSingle chat_model_conf = new ModelConfSingle("Chat and others",
                new ChatModelPreferences("chat"));

        chat_guess = new kingaidra.chat.Guess(ai, chat_model_conf, conf);

        decom_guess = new kingaidra.decom.Guess(ghidra, ai, chat_model_conf, conf);
        refactor = new kingaidra.decom.Refactor(ghidra, ai, new java.util.function.Function<String, String>() {
            @Override
            public String apply(String msg) {
                return msg;
            }
        });

        keyfunc_guess = new kingaidra.keyfunc.Guess(ghidra, ai, chat_model_conf, conf);

        if (verbose) {
            for (String model_name : chat_model_conf.get_models()) {
                if (chat_model_conf.get_model_status(model_name)) {
                    println(String.format("model name=%s, script=%s", model_name, chat_model_conf.get_model(model_name).get_script()));
                    break;
                }
            }
        }

        try {
            if (!analyze_function_auto()) {
                return;
            }

            report_function_auto();
        } catch (CancelledException e) {
        }
    }
}
