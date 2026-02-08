package kingaidra.ai.convo;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import ghidra.program.model.address.Address;
import kingaidra.ai.model.Model;


public class Conversation implements Serializable {

    public static final String SYSTEM_ROLE = "system";
    public static final String USER_ROLE = "user";
    public static final String ASSISTANT_ROLE = "assistant";
    public static final String TOOL_ROLE = "tool";

    private final UUID uuid;
    private ConversationType type;
    private Model model;
    private String created;
    private String updated;
    private List<Message> messages;
    private Set<Address> addrs;

    public Conversation(ConversationType type, Model model) {
        uuid = UUID.randomUUID();
        this.type = type;
        this.model = model;
        created = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        updated = created;
        messages = new LinkedList<>();
        addrs = new HashSet<>();
    }

    public Conversation(String uuid, ConversationType type, Model model, String created, String updated, Message[] msgs, Address[] addrs) {
        this.uuid = UUID.fromString(uuid);
        this.type = type;
        this.model = model;
        this.created = created;
        this.messages = new LinkedList<>();
        this.addrs = new HashSet<>();

        for (Message msg : msgs) {
            this.add_raw_msg(msg);
        }
        for (Address addr : addrs) {
            this.add_addr(addr);
        }

        this.updated = updated;
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

    public String get_created() {
        return created;
    }

    public String get_updated() {
        return updated;
    }

    public void set_updated(String updated) {
        this.updated = updated;
    }

    private void update_time() {
        set_updated(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
    }

    public String get_role(int idx) {
        if (idx >= messages.size()) {
            return null;
        }
        return messages.get(idx).get_role();
    }

    public String get_msg(int idx) {
        if (idx >= messages.size()) {
            return null;
        }
        return messages.get(idx).get_content();
    }

    public int get_msgs_len() {
        return messages.size();
    }

    public String get_tool_call_id(int idx) {
        if (idx >= messages.size()) {
            return null;
        }
        return messages.get(idx).get_tool_call_id();
    }

    public List<Map<String, Object>> get_tool_calls(int idx) {
        if (idx >= messages.size()) {
            return null;
        }
        return messages.get(idx).get_tool_calls();
    }

    public boolean add_system_msg(String content) {
        if (!messages.isEmpty()) {
            return false;
        }
        update_time();
        messages.add(new Message(SYSTEM_ROLE, content));
        return true;
    }

    public boolean add_msg(String role, String content) {
        if (role.equals(SYSTEM_ROLE)) {
            return add_system_msg(content);
        } else if (role.equals(USER_ROLE)) {
            return add_user_msg(content);
        } else if (role.equals(ASSISTANT_ROLE)) {
            return add_assistant_msg(content);
        } else if (role.equals(TOOL_ROLE)) {
            return add_tool_msg(content);
        }
        return false;
    }

    public boolean add_user_msg(String content) {
        if (!messages.isEmpty() && messages.get(get_msgs_len() - 1).get_role().equals(USER_ROLE)) {
            return false;
        }
        update_time();
        messages.add(new Message(USER_ROLE, content));
        return true;
    }

    public boolean add_assistant_msg(String content) {
        if (messages.isEmpty() || !messages.get(get_msgs_len() - 1).get_role().equals(USER_ROLE)) {
            return false;
        }
        update_time();
        messages.add(new Message(ASSISTANT_ROLE, content));
        return true;
    }

    public boolean add_tool_msg(String content) {
        update_time();
        messages.add(new Message(TOOL_ROLE, content));
        return true;
    }

    public boolean add_tool_msg(String tool_call_id, String content) {
        update_time();
        messages.add(new Message(TOOL_ROLE, content, tool_call_id, null));
        return true;
    }

    public boolean add_raw_msg(Message msg) {
        if (msg == null) {
            return false;
        }
        update_time();
        messages.add(msg);
        return true;
    }

    public boolean add_raw_msg(String role, String content) {
        update_time();
        messages.add(new Message(role, content));
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
