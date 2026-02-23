package kingaidra.decom;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelConf;
import kingaidra.ai.task.TaskType;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.PromptConf;

public class LlmDecompile {
    private static final int CONTEXT_FUNC_LIMIT = 8;
    private static final int REF_LIMIT = 24;

    private static final Pattern CODE_BLOCK_PATTERN = Pattern.compile(
            "```(?:c|cpp|cc|c\\+\\+)?\\s*(.*?)\\s*```",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private Ai ai;
    private GhidraUtil ghidra;
    private ModelConf model_conf;
    private PromptConf conf;

    public LlmDecompile(Ai ai, GhidraUtil ghidra, ModelConf model_conf, PromptConf conf) {
        this.ai = ai;
        this.ghidra = ghidra;
        this.model_conf = model_conf;
        this.conf = conf;
    }

    public String guess(Address addr) {
        return guess(addr, null, null);
    }

    public String guess(Address addr, String additional_instruction, String current_code) {
        if (addr == null) {
            return null;
        }
        Model model = get_active_model();
        if (model == null) {
            return null;
        }

        TaskType task = TaskType.DECOMPILE_VIEW;
        Conversation convo = new Conversation(ConversationType.SYSTEM_DECOMPILE_VIEW, model);
        convo.set_model(model);
        convo.add_system_msg(conf.get_system_prompt(task, model.get_name()));
        String msg = build_decompile_prompt(model, addr, additional_instruction, current_code);
        convo = ai.guess(task, convo, msg, addr);
        if (convo == null || convo.get_msgs_len() <= 0) {
            return null;
        }
        String rsp = convo.get_msg(convo.get_msgs_len() - 1);
        String code = normalize_code(rsp);
        return code;
    }

    private Model get_active_model() {
        for (String name : model_conf.get_models()) {
            Model model = model_conf.get_model(name);
            if (model != null && model.get_active()) {
                return model;
            }
        }
        return null;
    }

    private String build_decompile_prompt(Model model, Address addr, String additional_instruction, String current_code) {
        String base_prompt = build_decompile_prompt(model, addr);
        if (is_blank(additional_instruction) && is_blank(current_code)) {
            return base_prompt;
        }
        String instruction_prompt = conf.get_user_prompt(TaskType.DECOMPILE_VIEW_INSTRUCTION, model.get_name());
        if (is_blank(instruction_prompt)) {
            return base_prompt;
        }
        return base_prompt + "\n\n" + instruction_prompt
                .replace("<current_c_code>", is_blank(current_code) ? "" : current_code.trim())
                .replace("<instruction>", is_blank(additional_instruction) ? "" : additional_instruction.trim());
    }

    private String build_decompile_prompt(Model model, Address addr) {
        String prompt = conf.get_user_prompt(TaskType.DECOMPILE_VIEW, model.get_name());
        Function func = ghidra.get_func(addr);
        if (func == null) {
            return prompt;
        }
        Address entry = func.getEntryPoint();
        String entry_hex = Long.toHexString(entry.getOffset());

        StringBuilder msg = new StringBuilder(prompt);
        msg.append("\n\n# Related Function Context");
        msg.append("\n- Target function: ").append(func.getName())
                .append(" @ ").append(entry);
        msg.append("\n- Callers: ").append(format_function_list(ghidra.get_caller(func), CONTEXT_FUNC_LIMIT));
        msg.append("\n- Callees: ").append(format_function_list(ghidra.get_callee(func), CONTEXT_FUNC_LIMIT));

        msg.append("\n\n# Incoming References To Target Entry");
        msg.append("\n").append(build_entry_reference_summary(entry));

        msg.append("\n\n# Local Call Tree (Depth 2)");
        msg.append("\n<calltree:").append(entry_hex).append(":2>");

        msg.append("\n\n# Assembly Context (Target + Callees, addresses enabled)");
        msg.append("\n```asm\n<aasm:").append(entry_hex).append(":1>\n```");

        msg.append("\n\n# Ghidra Decompiled Reference (for cross-check only)");
        msg.append("\n```c\n<code:").append(entry_hex).append(">\n```");

        return msg.toString();
    }

    private String format_function_list(List<Function> funcs, int max) {
        if (funcs == null || funcs.isEmpty()) {
            return "(none)";
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (Function func : funcs) {
            if (func == null || func.getEntryPoint() == null) {
                continue;
            }
            if (count > 0) {
                sb.append(", ");
            }
            sb.append(func.getName()).append("@").append(func.getEntryPoint());
            count++;
            if (count >= max) {
                break;
            }
        }
        if (count <= 0) {
            return "(none)";
        }
        if (funcs.size() > count) {
            sb.append(", ...");
        }
        return sb.toString();
    }

    private String build_entry_reference_summary(Address entry) {
        List<Reference> refs = ghidra.get_ref_to(entry);
        if (refs == null || refs.isEmpty()) {
            return "(none)";
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (Reference ref : refs) {
            if (ref == null || ref.getFromAddress() == null) {
                continue;
            }
            if (count > 0) {
                sb.append("\n");
            }
            sb.append("- ").append(ref.getFromAddress())
                    .append(" [").append(ref.getReferenceType()).append("]");
            count++;
            if (count >= REF_LIMIT) {
                break;
            }
        }
        if (refs.size() > count) {
            sb.append("\n- ...");
        }
        return sb.toString();
    }

    private boolean is_blank(String text) {
        return text == null || text.trim().isEmpty();
    }

    public static String normalize_code(String code) {
        if (code == null) {
            return null;
        }
        Matcher matcher = CODE_BLOCK_PATTERN.matcher(code);
        if (matcher.find()) {
            String group = matcher.group(1);
            if (group != null) {
                return group.trim();
            }
        }
        return code.trim();
    }
}
