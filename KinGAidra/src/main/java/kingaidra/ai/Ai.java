package kingaidra.ai;

import java.lang.NumberFormatException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.BiFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.ai.task.TaskType;
import kingaidra.ghidra.PromptConf;
import kingaidra.ghidra.GhidraUtil;

public class Ai {
    private PluginTool tool;
    private Program program;
    private GhidraUtil ghidra;
    private ConversationContainer container;
    private KinGAidraChatTaskService service;
    private GhidraState state;
    private PromptConf conf;

    public Ai(PluginTool tool, Program program, GhidraUtil ghidra, ConversationContainer container,
            KinGAidraChatTaskService service, PromptConf conf) {
        this.tool = tool;
        this.program = program;
        this.ghidra = ghidra;
        this.container = container;
        this.service = service;
        this.conf = conf;
        this.state = null;
    }

    public void set_ghidra_state(GhidraState state) {
        this.state = state;
    }

    private String resolve_placeholder(String msg, Address addr, String placeholder, BiFunction<Long, Long, String> replace_func) {
        if (msg.contains("<" + placeholder + ">")) {
            Long addr_value = null;
            if (addr != null) {
                addr_value = addr.getOffset();
            }
            String replacement = replace_func.apply(addr_value, null);
            if (replacement != null) {
                msg = msg.replace("<" + placeholder + ">", replacement);
            }
        }

        Pattern pattern = Pattern.compile("<" + placeholder + ":([^:>]+)(:([0-9A-Fa-f]+))?>");
        Matcher matcher = pattern.matcher(msg);
        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            String arg1_str = matcher.group(1);
            List<Function> func_list = ghidra.get_func(arg1_str);
            long arg1_value;
            if (func_list.size() > 0) {
                arg1_value = func_list.get(0).getEntryPoint().getOffset();
            } else {
                try {
                    arg1_value = Long.parseLong(arg1_str, 16);
                } catch(NumberFormatException e) {
                    continue;
                }
            }

            String arg2_str = matcher.group(3);
            Long arg2_value = null;
            if (arg2_str != null) {
                arg2_value = Long.parseLong(arg2_str, 16);
            }

            String replacement = replace_func.apply(arg1_value, arg2_value);
            if (replacement == null) {
                matcher.appendReplacement(result, Matcher.quoteReplacement(matcher.group(0)));
            } else {
                matcher.appendReplacement(result, Matcher.quoteReplacement(replacement));
            }
        }
        matcher.appendTail(result);
        return result.toString();
    }

    public String resolve_asm_code(Conversation convo, String msg, Address addr) {
        return resolve_placeholder(msg, addr, "asm", new BiFunction<Long, Long, String>() {
            @Override
            public String apply(Long func_addr_value, Long depth) {
                Address func_addr = null;
                if (func_addr_value != null) {
                    func_addr = ghidra.get_addr(func_addr_value);
                }
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
                    if (depth != null) {
                        List<Function> callee_list = get_callee_upto_depth(match_func, depth);
                        for (Function cur_func : callee_list) {
                            asm_code += "\n\n";
                            asm_code += ghidra.get_asm(cur_func.getEntryPoint());
                        }
                    }
                }
                return asm_code;
            }
        });
    }

    public String resolve_asm_code_with_addr(Conversation convo, String msg, Address addr) {
        return resolve_placeholder(msg, addr, "aasm", new BiFunction<Long, Long, String>() {
            @Override
            public String apply(Long func_addr_value, Long depth) {
                Address func_addr = null;
                if (func_addr_value != null) {
                    func_addr = ghidra.get_addr(func_addr_value);
                }
                if (func_addr == null) {
                    return null;
                }
                String asm_code = ghidra.get_asm(func_addr, true);
                if (asm_code == null) {
                    return null;
                }
                Function match_func = ghidra.get_func(func_addr);
                if (match_func != null) {
                    convo.add_addr(match_func.getEntryPoint());
                    if (depth != null) {
                        List<Function> callee_list = get_callee_upto_depth(match_func, depth);
                        for (Function cur_func : callee_list) {
                            asm_code += "\n\n";
                            asm_code += ghidra.get_asm(cur_func.getEntryPoint(), true);
                        }
                    }
                }
                return asm_code;
            }
        });
    }

    public String resolve_src_code(Conversation convo, String msg, Address addr) {
        return resolve_placeholder(msg, addr, "code", new BiFunction<Long, Long, String>() {
            @Override
            public String apply(Long func_addr_value, Long depth) {
                Address func_addr = null;
                if (func_addr_value != null) {
                    func_addr = ghidra.get_addr(func_addr_value);
                }
                if (func_addr == null) {
                    return null;
                }
                String src_code = ghidra.get_decom(func_addr);
                if (src_code == null) {
                    return null;
                }
                Function match_func = ghidra.get_func(func_addr);
                if (match_func != null) {
                    convo.add_addr(match_func.getEntryPoint());
                }

                if (depth != null) {
                    List<Function> callee_list = get_callee_upto_depth(match_func, depth);
                    for (Function cur_func : callee_list) {
                        src_code += "\n\n";
                        src_code += ghidra.get_decom(cur_func.getEntryPoint());
                    }
                }

                return src_code;
            }
        });
    }

    private List<Function> get_callee_upto_depth(Function target, long depth) {
        if (target == null || depth <= 0) {
            return Collections.emptyList();
        }
        LinkedHashSet<Function> result = new LinkedHashSet<>();

        Set<Address> visited = new HashSet<>();
        Address targetAddr = target.getEntryPoint();
        visited.add(targetAddr);

        List<Function> current = new ArrayList<>(1);
        current.add(target);

        for (int d = 0; d < depth && !current.isEmpty(); d++) {
            List<Function> next = new ArrayList<>();
            for (int i = 0; i < current.size(); i++) {
                Function cur = current.get(i);
                List<Function> callees = ghidra.get_callee(cur);
                if (callees == null || callees.isEmpty()) {
                    continue;
                }

                for (int j = 0; j < callees.size(); j++) {
                    Function callee = callees.get(j);
                    if (callee == null) continue;

                    Address addr = callee.getEntryPoint();
                    if (addr == null || addr.equals(targetAddr)) {
                        continue;
                    }
                    if (visited.add(addr)) {
                        result.add(callee);
                        next.add(callee);
                    }
                }
            }
            current = next;
        }

        return new LinkedList<>(result);
    }

    public String resolve_calltree(Conversation convo, String msg, Address addr) {
        return resolve_placeholder(msg, addr, "calltree", new BiFunction<Long, Long, String>() {
            @Override
            public String apply(Long func_addr_value, Long depth) {
                String calltree;
                Address func_addr = null;
                if (func_addr_value != null) {
                    func_addr = ghidra.get_addr(func_addr_value);
                }
                if (func_addr == null) {
                    calltree = ghidra.get_func_call_tree();
                } else {
                    Function match_func = ghidra.get_func(func_addr);
                    if (depth != null) {
                        calltree = ghidra.get_func_call_tree(match_func, depth.intValue());
                    } else {
                        calltree = ghidra.get_func_call_tree(match_func);
                    }
                    if (calltree != null) {
                        convo.add_addr(match_func.getEntryPoint());
                    }
                }
                return calltree;
            }
        });
    }

    public String resolve_strings(Conversation convo, String msg) {
        return resolve_placeholder(msg, null, "strings", new BiFunction<Long, Long, String>() {
            @Override
            public String apply(Long index, Long num) {
                if (index == null) {
                    index = 0L;
                }
                if (num == null) {
                    num = -1L;
                }
                String calltree = ghidra.get_strings_str(index, num);
                return calltree;
            }
        });
    }

    public Conversation guess_explain_decom(Model m, Address addr) {
        TaskType task = TaskType.CHAT_EXPLAIN_DECOM;
        Conversation convo = new Conversation(ConversationType.USER_CHAT, m);
        convo.add_system_msg(conf.get_system_prompt(task, m.get_name()));
        String msg = conf.get_user_prompt(task, m.get_name());
        return guess(task, convo, msg, addr);
    }

    public Conversation guess_explain_asm(Model m, Address addr) {
        TaskType task = TaskType.CHAT_EXPLAIN_ASM;
        Conversation convo = new Conversation(ConversationType.USER_CHAT, m);
        convo.add_system_msg(conf.get_system_prompt(task, m.get_name()));
        String msg = conf.get_user_prompt(task, m.get_name());
        return guess(task, convo, msg, addr);
    }

    public Conversation guess_decom_asm(Model m, Address addr) {
        TaskType task = TaskType.CHAT_DECOM_ASM;
        Conversation convo = new Conversation(ConversationType.USER_CHAT, m);
        convo.add_system_msg(conf.get_system_prompt(task, m.get_name()));
        String msg = conf.get_user_prompt(task, m.get_name());
        return guess(task, convo, msg, addr);
    }

    public Conversation guess_explain_strings(Model m, Address addr) {
        TaskType task = TaskType.CHAT_EXPLAIN_STRINGS;
        Conversation convo = new Conversation(ConversationType.USER_CHAT, m);
        convo.add_system_msg(conf.get_system_prompt(task, m.get_name()));
        String msg = conf.get_user_prompt(task, m.get_name());
        return guess(task, convo, msg, addr);
    }

    public Conversation guess(TaskType type, Conversation convo, String msg, Address addr) {
        msg = resolve_src_code(convo, msg, addr);
        msg = resolve_asm_code(convo, msg, addr);
        msg = resolve_asm_code_with_addr(convo, msg, addr);
        msg = resolve_calltree(convo, msg, addr);
        msg = resolve_strings(convo, msg);
        convo.add_user_msg(msg);

        Conversation rep = convo.get_model().guess(type, convo, service, tool, program, state);
        if (rep != null) {
            container.add_convo(rep);
        }
        return rep;
    }

    public Conversation get_history_convo(UUID id) {
        return container.get_convo(id);
    }
}
