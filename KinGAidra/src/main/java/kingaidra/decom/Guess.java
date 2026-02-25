package kingaidra.decom;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelConf;
import kingaidra.ai.task.TaskType;
import kingaidra.decom.extractor.DataTypeJson;
import kingaidra.decom.extractor.DataTypeListJson;
import kingaidra.decom.extractor.FuncParamVarJson;
import kingaidra.decom.extractor.JsonExtractor;
import kingaidra.decom.extractor.ParamJson;
import kingaidra.decom.extractor.VarJson;
import kingaidra.ghidra.PromptConf;
import kingaidra.ghidra.GhidraUtil;

public class Guess {
    private GhidraUtil ghidra;
    private Ai ai;
    private ModelConf model_conf;
    private PromptConf conf;

    public Guess(GhidraUtil ghidra, Ai ai, ModelConf model_conf, PromptConf conf) {
        this.ghidra = ghidra;
        this.ai = ai;

        this.model_conf = model_conf;
        this.conf = conf;
    }

    public ModelConf get_model_conf() {
        return model_conf;
    }

    public DecomDiff guess(DecomDiff diff, boolean review) {
        return guess(diff, review, null);
    }

    public DecomDiff guess(DecomDiff diff, boolean review, String reference_code) {
        String ghidra_code = diff.get_src_code();
        String code_context = build_code_context(ghidra_code, reference_code);
        TaskType rename_task = resolve_rename_task(reference_code);
        TaskType datatype_task = resolve_datatype_task(reference_code);

        if (!guess_func_param_var(diff, review, code_context, ghidra_code, reference_code, rename_task)) {
            return null;
        }

        if (!guess_datatype(diff, review, code_context, ghidra_code, reference_code, datatype_task)) {
            return diff;
        }

        return diff;
    }

    private TaskType resolve_rename_task(String reference_code) {
        if (reference_code != null) {
            return TaskType.DECOM_VIEW_REFACTOR_FUNC_PARAM_VAR;
        }
        return TaskType.DECOM_REFACTOR_FUNC_PARAM_VAR;
    }

    private TaskType resolve_datatype_task(String reference_code) {
        if (reference_code != null) {
            return TaskType.DECOM_VIEW_REFACTOR_DATATYPE;
        }
        return TaskType.DECOM_REFACTOR_DATATYPE;
    }

    private String build_code_context(String ghidra_code, String reference_code) {
        if (reference_code == null) {
            return ghidra_code;
        }
        return "/* Refactoring target (Ghidra decompile). Keep orig_* identifiers from this block. */\n"
                + ghidra_code
                + "\n\n/* Semantic reference (DecompileView generated C). Use only as analysis hint. */\n"
                + reference_code;
    }

    private String apply_code_context(String prompt, String code_context,
            String ghidra_code, String reference_code) {
        String result = prompt;
        result = result.replace("<code>", code_context);
        result = result.replace("<ghidra_c_code>", ghidra_code == null ? "" : ghidra_code);
        result = result.replace("<decompile_view_c_code>", reference_code == null ? "" : reference_code);
        return result;
    }

    private String apply_review_response(String prompt, String rsp_msg) {
        return prompt.replace("%s", rsp_msg);
    }

    private boolean guess_func_param_var(DecomDiff diff, boolean review, String code_context,
            String ghidra_code, String reference_code, TaskType task) {
        Conversation convo = new Conversation(ConversationType.SYSTEM_DECOM, diff.get_model());
        convo.add_system_msg(conf.get_system_prompt(task, diff.get_model().get_name()));
        String explain_msg = apply_code_context(
                conf.get_user_prompt(TaskType.CHAT_EXPLAIN_DECOM, diff.get_model().get_name()),
                code_context, ghidra_code, reference_code);
        convo = ai.guess(task, convo, explain_msg, diff.get_addr());
        if (convo == null) {
            return false;
        }

        String msg = apply_code_context(
                conf.get_user_prompt(task, diff.get_model().get_name()),
                code_context,
                ghidra_code,
                reference_code);
        convo = ai.guess(task, convo, msg, diff.get_addr());
        if (convo == null) {
            return false;
        }

        String rsp_msg = convo.get_msg(convo.get_msgs_len() - 1);
        JsonExtractor<FuncParamVarJson> extractor = new JsonExtractor<>(rsp_msg, FuncParamVarJson.class);
        FuncParamVarJson func_json = extractor.get_data();
        if (func_json == null) {
            return false;
        }
        if (review) {
            TaskType review_task = TaskType.REVIEW_DECOM_REFACTOR_FUNC_PARAM_VAR;
            Conversation review_convo = new Conversation(ConversationType.SYSTEM_DECOM, diff.get_model());
            review_convo.add_system_msg(conf.get_system_prompt(review_task, diff.get_model().get_name()));
            String review_msg = apply_review_response(
                    apply_code_context(
                            conf.get_user_prompt(review_task, diff.get_model().get_name()),
                            code_context,
                            ghidra_code,
                            reference_code),
                    rsp_msg);
            review_convo = ai.guess(review_task, review_convo, review_msg, diff.get_addr());
            if (review_convo == null) {
                return false;
            }
            String review_rsp_msg = review_convo.get_msg(review_convo.get_msgs_len() - 1);
            if (!review_rsp_msg.replace(" ", "").contains("\"result\":true")) {
                return false;
            }
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

    private boolean guess_datatype(DecomDiff diff, boolean review, String code_context,
            String ghidra_code, String reference_code, TaskType task) {
        Conversation convo = new Conversation(ConversationType.SYSTEM_DECOM, diff.get_model());
        convo.add_system_msg(conf.get_system_prompt(task, diff.get_model().get_name()));
        String explain_msg = apply_code_context(
                conf.get_user_prompt(TaskType.CHAT_EXPLAIN_DECOM, diff.get_model().get_name()),
                code_context, ghidra_code, reference_code);
        convo = ai.guess(task, convo, explain_msg, diff.get_addr());
        if (convo == null) {
            return false;
        }

        String msg = apply_code_context(
                conf.get_user_prompt(task, diff.get_model().get_name()),
                code_context,
                ghidra_code,
                reference_code);
        convo = ai.guess(task, convo, msg, diff.get_addr());
        if (convo == null) {
            return false;
        }

        String rsp_msg = convo.get_msg(convo.get_msgs_len() - 1);
        JsonExtractor<DataTypeListJson> extractor = new JsonExtractor<>(rsp_msg, DataTypeListJson.class);
        DataTypeListJson datatype_json = extractor.get_data();
        if (datatype_json == null) {
            return false;
        }
        if (review) {
            TaskType review_task = TaskType.REVIEW_DECOM_REFACTOR_DATATYPE;
            Conversation review_convo = new Conversation(ConversationType.SYSTEM_DECOM, diff.get_model());
            review_convo.add_system_msg(conf.get_system_prompt(review_task, diff.get_model().get_name()));
            String review_msg = apply_review_response(
                    apply_code_context(
                            conf.get_user_prompt(review_task, diff.get_model().get_name()),
                            code_context,
                            ghidra_code,
                            reference_code),
                    rsp_msg);
            review_convo = ai.guess(review_task, review_convo, review_msg, diff.get_addr());
            if (review_convo == null) {
                return false;
            }
            String review_rsp_msg = review_convo.get_msg(review_convo.get_msgs_len() - 1);
            if (!review_rsp_msg.replace(" ", "").contains("\"result\":true")) {
                return false;
            }
        }
        for (DataTypeJson param : datatype_json) {
            diff.set_datatype_new_name(param.get_var_name(), param.get_new_datatype());
        }

        return true;
    }

    public DecomDiff guess(String name, DecomDiff diff) {
        return guess(name, diff, false);
    }

    public DecomDiff guess(String name, DecomDiff diff, boolean review) {
        return guess(name, diff, review, null);
    }

    public DecomDiff guess(String name, DecomDiff diff, boolean review, String reference_code) {
        Model m = model_conf.get_model(name);
        if (m == null) {
            return null;
        }
        diff.set_model(m);
        diff = guess(diff, review, reference_code);
        return diff;
    }

    public DecomDiff[] guess_all(Address addr) {
        return guess_all(addr, false);
    }

    public DecomDiff[] guess_all(Address addr, boolean review) {
        return guess_all(addr, review, null);
    }

    public DecomDiff[] guess_all(Address addr, boolean review, String reference_code) {
        List<DecomDiff> results = new ArrayList<>();
        DecomDiff diff = ghidra.get_decomdiff(addr);
        if (diff == null) {
            return results.toArray(new DecomDiff[] {});
        }
        for (String name : model_conf.get_models()) {
            Model model = model_conf.get_model(name);
            DecomDiff guessed = guess(model.get_name(), diff.clone(), review, reference_code);
            if (guessed == null) {
                continue;
            }
            results.add(guessed);
        }
        return results.toArray(new DecomDiff[] {});
    }

    public DecomDiff[] guess_selected(Address addr) {
        return guess_selected(addr, false);
    }

    public DecomDiff[] guess_selected(Address addr, boolean review) {
        return guess_selected(addr, review, null);
    }

    public DecomDiff[] guess_selected(Address addr, boolean review, String reference_code) {
        List<DecomDiff> results = new ArrayList<>();
        DecomDiff diff = ghidra.get_decomdiff(addr);
        if (diff == null) {
            return results.toArray(new DecomDiff[] {});
        }
        for (String name : model_conf.get_models()) {
            Model model = model_conf.get_model(name);
            if (!model.get_active()) {
                continue;
            }
            DecomDiff guessed = guess(model.get_name(), diff.clone(), review, reference_code);
            if (guessed == null) {
                continue;
            }
            results.add(guessed);
        }
        return results.toArray(new DecomDiff[] {});
    }

    public DecomDiff guess(String name, Address addr, boolean review) {
        return guess(name, addr, review, null);
    }

    public DecomDiff guess(String name, Address addr, boolean review, String reference_code) {
        DecomDiff diff = ghidra.get_decomdiff(addr);
        if (diff == null) {
            return null;
        }
        return guess(name, diff, review, reference_code);
    }
}
