package kingaidra.chat;

import ghidra.program.model.address.Address;

public interface ConversationContainer {

    // TODO: Address -> ID
    public Address[] get_addrs();

    public Conversation[] get_convo(Address addr);

    public void add_convo(Conversation convo);
}
