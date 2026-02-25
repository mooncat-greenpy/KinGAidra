package kingaidra.decom;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.task.TaskType;
import kingaidra.decom.extractor.ClangExtractor;
import kingaidra.ghidra.DataTypeParseResult;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.PromptConf;

public class Refactor {
    private static final int MAX_RESOLVE_DATATYPE_ATTEMPTS = 2;
    private static final int MAX_RETRY_TEXT = 8192;

    private GhidraUtil ghidra;
    private Ai ai;
    private PromptConf conf;
    private Function<String, String> fix_func;

    public Refactor(GhidraUtil ghidra, Ai ai, PromptConf conf, Function<String, String> fix_func) {
        this.ghidra = ghidra;
        this.ai = ai;
        this.conf = conf;
        this.fix_func = fix_func;
    }

    public DataType resolve_datatype(String datatype_name, Model model) {
        return resolve_datatype(datatype_name, model, null, null);
    }

    public DataType resolve_datatype(String datatype_name, Model model,
            String ghidra_code, String reference_code) {
        String target_name = normalize_datatype_name(datatype_name);
        if (target_name == null) {
            return null;
        }

        TaskType task = resolve_datatype_task(reference_code);
        Conversation convo = new Conversation(ConversationType.SYSTEM_DECOM, model);
        convo.add_system_msg(conf.get_system_prompt(task, model.get_name()));

        int bit_size = ghidra.get_addr(0).getSize();
        String msg = build_resolve_prompt(
                conf.get_user_prompt(task, model.get_name()),
                target_name,
                bit_size,
                ghidra_code,
                reference_code);

        for (int attempt = 1; attempt <= MAX_RESOLVE_DATATYPE_ATTEMPTS; attempt++) {
            convo = ai.guess(task, convo, msg, null);
            if (convo == null) {
                return null;
            }

            String rsp_msg = convo.get_msg(convo.get_msgs_len() - 1);
            String target = extract_target_code(rsp_msg);
            if (target == null) {
                if (attempt >= MAX_RESOLVE_DATATYPE_ATTEMPTS) {
                    return null;
                }
                msg = build_retry_prompt(target_name, bit_size, "", "No C definition found in previous output.",
                        ghidra_code, reference_code);
                continue;
            }

            DataTypeParseResult parse_result = ghidra.parse_datatypes_with_error(target);
            if (parse_result.is_success()) {
                return parse_result.get_datatype();
            }
            if (attempt >= MAX_RESOLVE_DATATYPE_ATTEMPTS) {
                return null;
            }

            String error_reason = "Ghidra parser failed.";
            if (parse_result.get_error_reason() != null) {
                error_reason = parse_result.get_error_reason().trim();
            }
            msg = build_retry_prompt(target_name, bit_size, target, error_reason,
                    ghidra_code, reference_code);
        }

        return null;
    }

    private TaskType resolve_datatype_task(String reference_code) {
        if (reference_code != null) {
            return TaskType.DECOM_VIEW_RESOLVE_DATATYPE;
        }
        return TaskType.DECOM_RESOLVE_DATATYPE;
    }

    public void refact(DecomDiff diff, boolean datatype_resolving) {
        refact(diff, datatype_resolving, null);
    }

    public void refact(DecomDiff diff, boolean datatype_resolving, String reference_code) {
        if (datatype_resolving) {
            Set<String> datatype_names = new HashSet<>();
            for (DiffPair pair : diff.get_datatypes()) {
                datatype_names.add(pair.get_new_name());
            }

            for (String datatype_name : datatype_names) {
                String name = normalize_datatype_name(datatype_name);
                if (name == null) {
                    continue;
                }

                List<DataType> dt_list = new LinkedList<>();
                ghidra.find_datatypes(datatype_name, dt_list);
                if (dt_list.size() > 0) {
                    continue;
                }
                dt_list = new LinkedList<>();
                ghidra.find_datatypes(name, dt_list);
                if (dt_list.size() > 0) {
                    continue;
                }

                DataType dt = resolve_datatype(name, diff.get_model(), diff.get_src_code(), reference_code);
                if (dt == null) {
                    continue;
                }
                ghidra.add_datatype(dt);
            }
        }

        ghidra.refact(diff);
    }

    private String extract_target_code(String rsp_msg) {
        if (rsp_msg == null) {
            return null;
        }

        String fixed = fix_func.apply(rsp_msg);
        if (fixed == null) {
            return null;
        }

        ClangExtractor extractor = new ClangExtractor(fixed);
        String target = extractor.get_data();
        if (target == null) {
            target = fixed;
        }
        return target;
    }

    private String normalize_datatype_name(String datatype_name) {
        String normalized = datatype_name.replaceAll("\\[[^\\]]*\\]", " ").trim();
        while (normalized.endsWith("*")) {
            normalized = normalized.substring(0, normalized.length() - 1).trim();
        }
        normalized = normalized.replaceAll("^(?i)(const|volatile)\\s+", "");
        normalized = normalized.replaceAll("^(?i)(struct|union|enum)\\s+", "");
        normalized = normalized.trim();
        if (normalized.contains(" ")) {
            String[] tokens = normalized.split("\\s+");
            normalized = tokens[tokens.length - 1];
        }
        if (normalized.isEmpty() || !normalized.matches("^[A-Za-z_][A-Za-z0-9_]*$")) {
            return null;
        }
        return normalized;
    }

    private String build_resolve_prompt(String template, String datatype_name, int bit_size,
            String ghidra_code, String reference_code) {
        return template
                .replace("<datatype_name>", datatype_name)
                .replace("<bit_size>", String.format("%d", bit_size))
                .replace("<ghidra_c_code>", ghidra_code == null ? "" : ghidra_code)
                .replace("<decompile_view_c_code>", reference_code == null ? "" : reference_code);
    }

    private String build_retry_prompt(String datatype_name, int bit_size,
            String previous_output, String failure_reason,
            String ghidra_code, String reference_code) {
        StringBuilder sb = new StringBuilder();
        sb.append("The previous struct definition failed to parse in Ghidra C parser.\n");
        sb.append("Please correct it and return valid C definitions.\n\n");
        sb.append("Target struct name: ").append(datatype_name).append("\n");
        sb.append("Target bit width: ").append(bit_size).append("\n\n");
        sb.append("# Failure reason\n");
        sb.append(trim_for_prompt(failure_reason)).append("\n\n");
        sb.append("# Previous output\n");
        sb.append("```c\n");
        sb.append(trim_for_prompt(previous_output)).append("\n");
        sb.append("```\n");

        if (ghidra_code != null) {
            sb.append("\n# Ghidra Decompiled Target\n");
            sb.append("```c\n");
            sb.append(trim_for_prompt(ghidra_code)).append("\n");
            sb.append("```\n");
        }
        if (reference_code != null) {
            sb.append("\n# DecompileView Generated C\n");
            sb.append("```c\n");
            sb.append(trim_for_prompt(reference_code)).append("\n");
            sb.append("```\n");
        }

        sb.append("\nConstraints:\n");
        sb.append("- Include dependent types only if required.\n");
        sb.append("- Keep the target struct name exactly as requested.\n");
        sb.append("- Output C code only.\n");
        return sb.toString();
    }

    private String trim_for_prompt(String text) {
        String normalized = text.trim();
        if (normalized.length() <= MAX_RETRY_TEXT) {
            return normalized;
        }
        return normalized.substring(0, MAX_RETRY_TEXT);
    }
}
