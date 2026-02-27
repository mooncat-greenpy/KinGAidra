package kingaidra.chat;

import java.util.AbstractMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelConf;
import kingaidra.ai.task.TaskType;
import kingaidra.chat.workflow.ChatWorkflow;
import kingaidra.decom.extractor.CommentJson;
import kingaidra.decom.extractor.CommentListJson;
import kingaidra.decom.extractor.JsonExtractor;
import kingaidra.ghidra.PromptConf;

public class Guess {
    private static final int MALWARE_OVERVIEW_ADDITIONAL_MAX_TRIES = 3;

    private Ai ai;
    private ModelConf model_conf;
    private PromptConf conf;

    public Guess(Ai ai, ModelConf model_conf, PromptConf conf) {
        this.ai = ai;

        this.model_conf = model_conf;
        this.conf = conf;
    }

    public ModelConf get_model_conf() {
        return model_conf;
    }

    private Model get_active_model() {
        for (String name : model_conf.get_models()) {
            Model tmp = model_conf.get_model(name);
            if (tmp != null && tmp.get_active()) {
                return tmp;
            }
        }
        return null;
    }

    public Conversation guess(TaskType type, Conversation convo, String msg, Address addr) {
        convo = ai.guess(type, convo, msg, addr);
        return convo;
    }

    public Conversation guess(TaskType type, String msg, Address addr) {
        Model m = get_active_model();
        if (m == null) {
            return null;
        }
        Conversation convo = new Conversation(ConversationType.USER_CHAT, m);
        convo.add_system_msg(conf.get_system_prompt(type, m.get_name()));

        if (type == TaskType.CHAT_EXPLAIN_DECOM) {
            return ai.guess_explain_decom(m, addr);
        } else if (type == TaskType.CHAT_EXPLAIN_ASM) {
            return ai.guess_explain_asm(m, addr);
        } else if (type == TaskType.CHAT_DECOM_ASM) {
            return ai.guess_decom_asm(m, addr);
        } else if (type == TaskType.CHAT_EXPLAIN_STRINGS) {
            return ai.guess_explain_strings(m, addr);
        } else if (type == TaskType.CHAT_MALWARE_BEHAVIOR_OVERVIEW) {
            return guess_malware_behavior_overview(type, convo, m.get_name(), addr);
        }
        return guess(type, convo, msg, addr);
    }

    private Conversation guess_malware_behavior_overview(
            TaskType type, Conversation convo, String model_name, Address addr) {
        Conversation result = ai.guess(
                type,
                convo,
                conf.get_user_prompt(TaskType.CHAT_MALWARE_BEHAVIOR_OVERVIEW, model_name),
                addr);
        if (result == null) {
            return null;
        }

        String additional_prompt = conf.get_user_prompt(TaskType.CHAT_MALWARE_BEHAVIOR_OVERVIEW_ADDITIONAL, model_name);
        for (int i = 0; i < MALWARE_OVERVIEW_ADDITIONAL_MAX_TRIES; i++) {
            result = ai.guess(TaskType.CHAT_MALWARE_BEHAVIOR_OVERVIEW_ADDITIONAL, result, additional_prompt, addr);
            if (result == null) {
                return null;
            }
            if (is_last_assistant_message_none(result)) {
                break;
            }
        }

        return ai.guess(
                TaskType.CHAT_MALWARE_BEHAVIOR_OVERVIEW_REPORT,
                result,
                conf.get_user_prompt(TaskType.CHAT_MALWARE_BEHAVIOR_OVERVIEW_REPORT, model_name),
                addr);
    }

    private boolean is_last_assistant_message_none(Conversation convo) {
        return "None".equalsIgnoreCase(convo.get_msg(convo.get_msgs_len() - 1).trim());
    }

    public Conversation guess_workflow(ChatWorkflow workflow, Address addr) {
        if (workflow == null || workflow.get_step_prompts().isEmpty()) {
            return null;
        }

        Model m = get_active_model();
        if (m == null) {
            return null;
        }

        Conversation convo = new Conversation(ConversationType.USER_CHAT, m);
        String workflow_system_prompt = workflow.get_system_prompt();
        if (workflow_system_prompt.isEmpty()) {
            workflow_system_prompt = conf.get_system_prompt(TaskType.CHAT, m.get_name());
        }
        convo.add_system_msg(workflow_system_prompt);

        Conversation result = convo;
        for (String prompt : workflow.get_step_prompts()) {
            result = ai.guess(TaskType.CHAT, result, prompt, addr);
            if (result == null) {
                return null;
            }
        }
        return result;
    }

    public List<Map.Entry<String, String>> guess_src_code_comments(Address addr) {
        List<Map.Entry<String, String>> comments = new LinkedList<>();

        Model m = get_active_model();
        if (m == null) {
            return comments;
        }

        TaskType task = TaskType.ADD_COMMENTS;
        Conversation convo = new Conversation(ConversationType.SYSTEM_COMMENT, m);
        convo.add_system_msg(conf.get_system_prompt(task, m.get_name()));
        String msg = conf.get_user_prompt(task, m.get_name());

        convo = ai.guess(TaskType.ADD_COMMENTS, convo, msg, addr);
        if (convo == null) {
            return comments;
        }
        JsonExtractor<CommentListJson> extractor = new JsonExtractor<>(convo.get_msg(convo.get_msgs_len() - 1), CommentListJson.class);
        CommentListJson comment_list_json = extractor.get_data();
        if (comment_list_json == null) {
            return comments;
        }
        for (CommentJson comment_json : comment_list_json) {
            comments.add(new AbstractMap.SimpleEntry<>(comment_json.get_source(), comment_json.get_comment()));
        }
        return comments;
    }
}
