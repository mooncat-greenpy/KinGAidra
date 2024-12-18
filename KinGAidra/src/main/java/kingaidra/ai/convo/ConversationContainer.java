package kingaidra.ai.convo;

import java.util.UUID;

public interface ConversationContainer {

    // TODO: Address -> ID
    public UUID[] get_ids();

    public Conversation get_convo(UUID uuid);

    public void add_convo(Conversation convo);
}
