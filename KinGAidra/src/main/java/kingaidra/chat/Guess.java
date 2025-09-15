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
import kingaidra.decom.extractor.CommentJson;
import kingaidra.decom.extractor.CommentListJson;
import kingaidra.decom.extractor.JsonExtractor;

public class Guess {
    private Ai ai;
    private ModelConf model_conf;

    public Guess(Ai ai, ModelConf conf) {
        this.ai = ai;

        model_conf = conf;
    }

    public ModelConf get_model_conf() {
        return model_conf;
    }

    public Conversation guess(TaskType type, Conversation convo, String msg, Address addr) {
        convo = ai.guess(type, convo, msg, addr);
        return convo;
    }

    public Conversation guess(TaskType type, String msg, Address addr) {
        Model m = null;
        for (String name : model_conf.get_models()) {
            Model tmp = model_conf.get_model(name);
            if (tmp.get_active()) {
                m = tmp;
                break;
            }
        }
        if (m == null) {
            return null;
        }
        Conversation convo = new Conversation(ConversationType.USER_CHAT, m);
        convo.set_model(m);

        if (type == TaskType.CHAT_EXPLAIN_DECOM) {
            return ai.guess_explain_decom(m, addr);
        } else if (type == TaskType.CHAT_EXPLAIN_ASM) {
            return ai.guess_explain_asm(m, addr);
        } else if (type == TaskType.CHAT_DECOM_ASM) {
            return ai.guess_decom_asm(m, addr);
        } else if (type == TaskType.CHAT_EXPLAIN_STRINGS) {
            return ai.guess_explain_strings(m, addr);
        }
        return guess(type, convo, msg, addr);
    }

    public List<Map.Entry<String, String>> guess_src_code_comments(Address addr) {
        List<Map.Entry<String, String>> comments = new LinkedList<>();

        Model m = null;
        for (String name : model_conf.get_models()) {
            Model tmp = model_conf.get_model(name);
            if (tmp.get_active()) {
                m = tmp;
                break;
            }
        }
        if (m == null) {
            return comments;
        }

        Conversation convo = new Conversation(ConversationType.SYSTEM_COMMENT, m);
        String msg = "Please add comments to the following C language function to explain its purpose and logic. The comments should be concise but clear, and should describe the function, parameters, logic, and any important details for each part of the code. Return the results in the following format:\n" +
                        "\n" +
                        "```json\n" +
                        "[\n" +
                        "    {\n" +
                        "        \"source\": \"source code line A\",\n" +
                        "        \"comment\": \"comment A\"\n" +
                        "    },\n" +
                        "    {\n" +
                        "        \"source\": \"source code line B\",\n" +
                        "        \"comment\": \"comment B\"\n" +
                        "    },\n" +
                        "    ...\n" +
                        "]\n" +
                        "```\n" +
                        "\n" +
                        "Here is the C code:\n" +
                        "\n" +
                        "```cpp\n" +
                        "<code>\n" +
                        "```";

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
