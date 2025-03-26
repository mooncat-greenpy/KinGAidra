//@author mooncat-greenpy
//@category KinGAidra
//@keybinding 
//@menupath 
//@toolbar 


import java.util.HashSet;
import java.util.List;
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

    private GhidraUtil ghidra;
    private kingaidra.decom.Guess decom_guess;
    private kingaidra.decom.Refactor refactor;
    private kingaidra.keyfunc.Guess keyfunc_guess;

    private void analyze_func(Function func) throws Exception {
        println("Refactoring: " + func.getName());
        DecomDiff[] diff_arr = decom_guess.guess_selected(func.getEntryPoint());
        if (diff_arr.length < 1) {
            return;
        }
        refactor.refact(diff_arr[0], false);
        Thread.sleep(1000*60);
    }

    public void run() throws Exception {
        KinGAidraChatTaskService srv = state.getTool().getService(KinGAidraChatTaskService.class);
        PluginTool tool = state.getTool();
        ghidra = new GhidraUtilImpl(currentProgram, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerGhidraProgram(currentProgram, ghidra);
        Ai ai = new Ai(tool, currentProgram, ghidra, container, srv);
        ModelConfSingle chat_model_conf = new ModelConfSingle("Chat and others",
                new ChatModelPreferences("chat"));
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
                analyze_func(func);
            }
        }
    }
}
