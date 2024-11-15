package kingaidra.chat;

import java.util.LinkedList;
import java.util.List;

import kingaidra.chat.ai.Model;


class Message {

    private String role;
    private String content;

    public Message(String role, String content) {
        this.role = role;
        this.content = content;
    }

    public String get_role() {
        return role;
    }

    public String get_content() {
        return content;
    }
}


public class Conversation {

    public static final String SYSTEM_ROLE = "system";
    public static final String USER_ROLE = "user";
    public static final String ASSISTANT_ROLE = "assistant";

    private Model model;
    private List<Message> msgs;

    public Conversation(Model model) {
        msgs = new LinkedList<>();
        this.model = model;
    }

    public Model get_model() {
        return model;
    }

    public void set_model(Model model) {
        this.model = model;
    }

    public String get_role(int idx) {
        if (idx >= msgs.size()) {
            return null;
        }
        return msgs.get(idx).get_role();
    }

    public String get_msg(int idx) {
        if (idx >= msgs.size()) {
            return null;
        }
        return msgs.get(idx).get_content();
    }

    public int get_msgs_len() {
        return msgs.size();
    }

    public boolean add_system_msg(String content) {
        if (!msgs.isEmpty()) {
            return false;
        }
        msgs.add(new Message(SYSTEM_ROLE, content));
        return true;
    }

    public boolean add_user_msg(String content) {
        if (!msgs.isEmpty() && msgs.get(get_msgs_len() - 1).get_role().equals(USER_ROLE)) {
            return false;
        }
        msgs.add(new Message(USER_ROLE, content));
        return true;
    }

    public boolean add_assistant_msg(String content) {
        if (msgs.isEmpty() || !msgs.get(get_msgs_len() - 1).get_role().equals(USER_ROLE)) {
            return false;
        }
        msgs.add(new Message(ASSISTANT_ROLE, content));
        return true;
    }
}
