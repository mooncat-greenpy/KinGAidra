package kingaidra.ai.convo;

import java.io.Serializable;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import ghidra.program.model.address.Address;
import kingaidra.ai.model.Model;


class Message implements Serializable {

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


public class Conversation implements Serializable {

    public static final String SYSTEM_ROLE = "system";
    public static final String USER_ROLE = "user";
    public static final String ASSISTANT_ROLE = "assistant";

    private final UUID uuid;
    private ConversationType type;
    private Model model;
    private List<Message> msgs;
    private Set<Address> addrs;

    public Conversation(ConversationType type, Model model) {
        uuid = UUID.randomUUID();
        msgs = new LinkedList<>();
        addrs = new HashSet<>();
        this.type = type;
        this.model = model;
    }

    public Conversation(String uuid, ConversationType type, Model model) {
        this.uuid = UUID.fromString(uuid);
        msgs = new LinkedList<>();
        addrs = new HashSet<>();
        this.type = type;
        this.model = model;
    }

    public UUID get_uuid() {
        return uuid;
    }

    public ConversationType get_type() {
        return type;
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

    public boolean add_msg(String role, String content) {
        if (role.equals(SYSTEM_ROLE)) {
            return add_system_msg(content);
        } else if (role.equals(USER_ROLE)) {
            return add_user_msg(content);
        } else if (role.equals(ASSISTANT_ROLE)) {
            return add_assistant_msg(content);
        }
        return false;
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

    public Address[] get_addrs() {
        return addrs.toArray(new Address[] {});
    }

    public void add_addr(Address addr) {
        addrs.add(addr);
    }

    @Override
    public String toString() {
        String s = "";
        for (int i = 0; i < get_msgs_len(); i++) {
            s += get_role(i) + ": " + get_msg(i) + "\n";
        }
        return s;
    }
}
