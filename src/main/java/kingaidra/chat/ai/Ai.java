package kingaidra.chat.ai;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import kingaidra.ai.TaskType;
import kingaidra.chat.Conversation;
import kingaidra.chat.ConversationContainer;
import kingaidra.chat.KinGAidraChatTaskService;
import kingaidra.ghidra.GhidraUtil;

public class Ai {
    private PluginTool tool;
    private Program program;
    private GhidraUtil ghidra;
    private ConversationContainer container;
    private KinGAidraChatTaskService service;

    public Ai(PluginTool tool, Program program, GhidraUtil ghidra, ConversationContainer container, KinGAidraChatTaskService service) {
        this.tool = tool;
        this.program = program;
        this.ghidra = ghidra;
        this.container = container;
        this.service = service;
    }

    public String resolve_asm_code(Conversation convo, String msg, Address addr) {
        Function func = ghidra.get_func(addr);
        String asm_code = ghidra.get_asm(addr);
        if (func == null || asm_code == null) {
            return msg;
        }
        if (msg.contains("<asm>")) {
            msg = msg.replace("<asm>", asm_code);
            convo.add_addr(func.getEntryPoint());
        }

        Pattern code_pattern = Pattern.compile("<asm:([0-9A-Fa-f]+)>");
        Matcher code_matcher = code_pattern.matcher(msg);
        StringBuffer result = new StringBuffer();
        while (code_matcher.find()) {
            String addr_str = code_matcher.group(1);
            long addr_value = Long.parseLong(addr_str, 16);
            Address match_addr = ghidra.get_addr(addr_value);
            Function match_func = ghidra.get_func(match_addr);
            String match_asm_code = ghidra.get_asm(match_addr);
            if (match_func == null || match_asm_code == null) {
                continue;
            }
            code_matcher.appendReplacement(result, match_asm_code);
            convo.add_addr(match_func.getEntryPoint());
        }
        code_matcher.appendTail(result);
        return result.toString();
    }

    public String resolve_src_code(Conversation convo, String msg, Address addr) {
        Function func = ghidra.get_func(addr);
        String src_code = ghidra.get_decom(addr);
        if (func == null || src_code == null) {
            return msg;
        }
        if (msg.contains("<code>")) {
            msg = msg.replace("<code>", src_code);
            convo.add_addr(func.getEntryPoint());
        }

        Pattern code_pattern = Pattern.compile("<code:([0-9A-Fa-f]+)>");
        Matcher code_matcher = code_pattern.matcher(msg);
        StringBuffer result = new StringBuffer();
        while (code_matcher.find()) {
            String addr_str = code_matcher.group(1);
            long addr_value = Long.parseLong(addr_str, 16);
            Address match_addr = ghidra.get_addr(addr_value);
            Function match_func = ghidra.get_func(match_addr);
            String match_src_code = ghidra.get_decom(match_addr);
            if (match_func == null || match_src_code == null) {
                continue;
            }
            code_matcher.appendReplacement(result, match_src_code);
            convo.add_addr(match_func.getEntryPoint());
        }
        code_matcher.appendTail(result);
        return result.toString();
    }

    public Conversation guess(Conversation convo, String msg, Address addr) {
        msg = resolve_src_code(convo, msg, addr);
        msg = resolve_asm_code(convo, msg, addr);
        convo.add_user_msg(msg);

        Conversation rep = convo.get_model().guess(TaskType.CHAT, convo, service, tool, program);
        if (rep != null) {
            container.add_convo(rep);
        }
        return rep;
    }
}
