package kingaidra.chat;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;

public class ConversationContainerDummy implements ConversationContainer {

    private Map<Address, List<Conversation>> data;

    public ConversationContainerDummy() {
        data = new HashMap<>();
    }

    public Address[] get_addrs() {
        return data.keySet().toArray(new Address[] {});
    }

    public Conversation[] get_convo(Address addr) {
        return data.get(addr).toArray(new Conversation[] {});
    }

    public void add_convo(Conversation convo) {
        for (Address addr : convo.get_addrs()) {
            List<Conversation> l = data.get(addr);
            if (l != null) {
                l.add(convo);
            } else {
                l = new LinkedList<>();
                l.add(convo);
            }
            data.put(addr, l);
        }
    }
}
