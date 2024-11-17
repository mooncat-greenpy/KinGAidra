package kingaidra.chat;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class ConversationContainerDummy implements ConversationContainer {

    private Map<UUID, Conversation> data;

    public ConversationContainerDummy() {
        data = new HashMap<>();
    }

    public UUID[] get_ids() {
        return data.keySet().toArray(new UUID[] {});
    }

    public Conversation get_convo(UUID id) {
        return data.get(id);
    }

    public void add_convo(Conversation convo) {
        data.put(convo.get_uuid(), convo);
    }
}
