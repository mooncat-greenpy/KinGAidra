//@author mooncat-greenpy
//@category KinGAidra
//@keybinding 
//@menupath 
//@toolbar 


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
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

import kingaidra.ai.Ai;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerGhidraProgram;
import kingaidra.ai.model.ModelConfSingle;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.decom.DecomDiff;
import kingaidra.ghidra.ChatModelPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;


public class kingaidra_auto extends GhidraScript {

    private static int INTERVAL_MILLISECOND = 1000*60;
    private static int CALLED_RECURSIVE_COUNT = 4;
    private static int CALLING_RECURSIVE_COUNT = 4;
    private GhidraUtil ghidra;
    private kingaidra.chat.Guess chat_guess;
    private kingaidra.decom.Guess decom_guess;
    private kingaidra.decom.Refactor refactor;
    private kingaidra.keyfunc.Guess keyfunc_guess;

    private boolean refactoring(Function func) {
        DecomDiff[] diff_arr = decom_guess.guess_selected(func.getEntryPoint());
        if (diff_arr.length < 1) {
            return false;
        }
        refactor.refact(diff_arr[0], false);
        return true;
    }

    private boolean add_comments(Function func) {
        List<Map.Entry<String, String>> comments = chat_guess.guess_src_code_comments(func.getEntryPoint());
        if (comments.size() < 1) {
            return false;
        }
        ghidra.add_comments(func.getEntryPoint(), comments);
        return true;
    }

    private void analyze_func(Function func) throws Exception {
        println("Refactoring: " + func.getName());

        if (!refactoring(func)) {
            Thread.sleep(INTERVAL_MILLISECOND);
            if (!refactoring(func)) {
                return;
            }
        }

        Thread.sleep(INTERVAL_MILLISECOND);

        ghidra.clear_comments(func.getEntryPoint());
        if (!add_comments(func)) {
            Thread.sleep(INTERVAL_MILLISECOND);
            if (!add_comments(func)) {
                return;
            }
        }

        Thread.sleep(INTERVAL_MILLISECOND);
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
            add_called_func_recur(analyze_func_list, calling_func, CALLED_RECURSIVE_COUNT);
            add_func(analyze_func_list, calling_func);
            add_calling_func_recur(analyze_func_list, calling_func, recur_count - 1);
        }
    }

    public void run() throws Exception {
        List<Function> analyze_func_list = new LinkedList();

        KinGAidraChatTaskService srv = state.getTool().getService(KinGAidraChatTaskService.class);
        PluginTool tool = state.getTool();
        ghidra = new GhidraUtilImpl(currentProgram, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerGhidraProgram(currentProgram, ghidra);
        Ai ai = new Ai(tool, currentProgram, ghidra, container, srv);
        ModelConfSingle chat_model_conf = new ModelConfSingle("Chat and others",
                new ChatModelPreferences("chat"));
        chat_guess = new kingaidra.chat.Guess(ai, chat_model_conf);

        decom_guess = new kingaidra.decom.Guess(ghidra, ai, chat_model_conf);
        refactor = new kingaidra.decom.Refactor(ghidra, ai, new java.util.function.Function<String, String>() {
            @Override
            public String apply(String msg) {
                return msg;
            }
        });
        keyfunc_guess = new kingaidra.keyfunc.Guess(ghidra, ai, chat_model_conf);

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

                add_called_func_recur(analyze_func_list, func, CALLED_RECURSIVE_COUNT);

                add_func(analyze_func_list, func);

                add_calling_func_recur(analyze_func_list, func, CALLING_RECURSIVE_COUNT);
            }
        }
        for (Function func : analyze_func_list) {
            analyze_func(func);
        }
    }
}
