package kingaidra.ai;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.ai.task.TaskType;
import kingaidra.ghidra.GhidraUtil;

public class Ai {
    private PluginTool tool;
    private Program program;
    private GhidraUtil ghidra;
    private ConversationContainer container;
    private KinGAidraChatTaskService service;
    private GhidraState state;

    public Ai(PluginTool tool, Program program, GhidraUtil ghidra, ConversationContainer container,
            KinGAidraChatTaskService service) {
        this.tool = tool;
        this.program = program;
        this.ghidra = ghidra;
        this.container = container;
        this.service = service;
        this.state = null;
    }

    public void set_ghidra_state(GhidraState state) {
        this.state = state;
    }

    private String resolve_placeholder(String msg, Address addr, String placeholder, java.util.function.Function<Address, String> replace_func) {
        if (msg.contains("<" + placeholder + ">")) {
            String replacement = replace_func.apply(addr);
            if (replacement != null) {
                msg = msg.replace("<" + placeholder + ">", replacement);
            }
        }

        Pattern pattern = Pattern.compile("<" + placeholder + ":([0-9A-Fa-f]+)>");
        Matcher matcher = pattern.matcher(msg);
        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            String addr_str = matcher.group(1);
            long addr_value = Long.parseLong(addr_str, 16);
            Address match_addr = ghidra.get_addr(addr_value);
            String replacement = replace_func.apply(match_addr);
            if (replacement == null) {
                continue;
            }
            matcher.appendReplacement(result, replacement);
        }
        matcher.appendTail(result);
        return result.toString();
    }

    public String resolve_asm_code(Conversation convo, String msg, Address addr) {
        return resolve_placeholder(msg, addr, "asm", new java.util.function.Function<Address, String>() {
            @Override
            public String apply(Address func_addr) {
                if (func_addr == null) {
                    return null;
                }
                String asm_code = ghidra.get_asm(func_addr);
                if (asm_code == null) {
                    return null;
                }
                Function match_func = ghidra.get_func(func_addr);
                if (match_func != null) {
                    convo.add_addr(match_func.getEntryPoint());
                }
                return asm_code;
            }
        });
    }

    public String resolve_src_code(Conversation convo, String msg, Address addr) {
        return resolve_placeholder(msg, addr, "code", new java.util.function.Function<Address, String>() {
            @Override
            public String apply(Address func_addr) {
                if (func_addr == null) {
                    return null;
                }
                String src_code = ghidra.get_decom(func_addr);
                if (src_code == null) {
                    return null;
                }
                Function match_func = ghidra.get_func(func_addr);
                convo.add_addr(match_func.getEntryPoint());
                return src_code;
            }
        });
    }

    public String resolve_calltree(Conversation convo, String msg, Address addr) {
        return resolve_placeholder(msg, addr, "calltree", new java.util.function.Function<Address, String>() {
            @Override
            public String apply(Address func_addr) {
                String calltree;
                if (func_addr == null) {
                    calltree = ghidra.get_func_call_tree();
                } else {
                    Function match_func = ghidra.get_func(func_addr);
                    calltree = ghidra.get_func_call_tree(match_func);
                    if (calltree != null) {
                        convo.add_addr(match_func.getEntryPoint());
                    }
                }
                return calltree;
            }
        });
    }

    public String resolve_strings(Conversation convo, String msg) {
        return resolve_placeholder(msg, null, "strings", new java.util.function.Function<Address, String>() {
            @Override
            public String apply(Address addr) {
                String calltree = ghidra.get_strings_str();
                return calltree;
            }
        });
    }

    public Conversation guess(TaskType type, Conversation convo, String msg, Address addr) {
        msg = resolve_src_code(convo, msg, addr);
        msg = resolve_asm_code(convo, msg, addr);
        msg = resolve_calltree(convo, msg, addr);
        msg = resolve_strings(convo, msg);
        convo.add_user_msg(msg);

        Conversation rep = convo.get_model().guess(type, convo, service, tool, program, state);
        if (rep != null) {
            container.add_convo(rep);
        }
        return rep;
    }
}
