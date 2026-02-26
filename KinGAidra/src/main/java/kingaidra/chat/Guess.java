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
            String overview_prompt = conf.get_user_prompt(type, m.get_name());
            return guess(type, convo, overview_prompt, addr);
        }
        return guess(type, convo, msg, addr);
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
