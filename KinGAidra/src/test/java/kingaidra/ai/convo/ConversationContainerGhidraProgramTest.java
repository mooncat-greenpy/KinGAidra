package kingaidra.ai.convo;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.UUID;

import ghidra.program.model.listing.Program;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainerGhidraProgram;
import kingaidra.testutil.GhidraTestUtil;
import kingaidra.testutil.ModelDummy;

public class ConversationContainerGhidraProgramTest {
    @Test
    void test() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        ConversationContainerGhidraProgram container =
                new ConversationContainerGhidraProgram(program);
        Conversation convo = new Conversation(new ModelDummy("Dummy", "dummy.py", true));
        container.add_convo(convo);

        Conversation result = container.get_convo(convo.get_uuid());
        assertEquals(convo.get_uuid(), result.get_uuid());
        assertEquals(convo.get_model().get_name(), result.get_model().get_name());
        assertEquals(convo.get_msgs_len(), result.get_msgs_len());
        assertEquals(convo.get_role(0), result.get_role(0));
        assertEquals(convo.get_msg(0), result.get_msg(0));
        assertEquals(convo.get_addrs().length, result.get_addrs().length);
    }

    @Test
    void test_one() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        ConversationContainerGhidraProgram container =
                new ConversationContainerGhidraProgram(program);
        Conversation convo = new Conversation(new ModelDummy("Dummy", "dummy.py", true));
        convo.add_user_msg("user_msg");
        convo.add_assistant_msg("assistant_msg");
        convo.add_addr(util.get_addr(program, 0x401000));
        container.add_convo(convo);

        UUID[] uuids = container.get_ids();
        assertEquals(uuids.length, 1);
        assertEquals(uuids[0], convo.get_uuid());

        Conversation result = container.get_convo(convo.get_uuid());
        assertEquals(convo.get_uuid(), result.get_uuid());
        assertEquals(convo.get_model().get_name(), result.get_model().get_name());
        assertEquals(convo.get_msgs_len(), result.get_msgs_len());
        for (int i = 0; i < convo.get_msgs_len(); i++) {
            assertEquals(convo.get_role(i), result.get_role(i));
            assertEquals(convo.get_msg(i), result.get_msg(i));
        }
        assertEquals(convo.get_addrs().length, result.get_addrs().length);
        for (int i = 0; i < convo.get_addrs().length; i++) {
            assertEquals(convo.get_addrs()[i], result.get_addrs()[i]);
        }
    }

    @Test
    void test_two() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        ConversationContainerGhidraProgram container =
                new ConversationContainerGhidraProgram(program);

        Conversation convo1 = new Conversation(new ModelDummy("Dummy", "dummy.py", true));
        convo1.add_user_msg("user_msg");
        convo1.add_assistant_msg("assistant_msg");
        convo1.add_addr(util.get_addr(program, 0x401000));
        container.add_convo(convo1);

        UUID[] uuids1 = container.get_ids();
        assertEquals(uuids1.length, 1);

        Conversation convo2 = new Conversation(new ModelDummy("Dummy", "dummy.py", true));
        convo2.add_system_msg("system_msg");
        convo2.add_user_msg("user_msg");
        convo2.add_assistant_msg("assistant_msg");
        convo2.add_user_msg("user_msg2");
        convo2.add_assistant_msg("assistant_msg2");
        convo2.add_addr(util.get_addr(program, 0x401000));
        convo2.add_addr(util.get_addr(program, 0x402000));
        container.add_convo(convo2);

        UUID[] uuids2 = container.get_ids();
        assertEquals(uuids2.length, 2);

        Conversation result1 = container.get_convo(convo1.get_uuid());
        assertEquals(convo1.get_uuid(), result1.get_uuid());
        assertEquals(convo1.get_model().get_name(), result1.get_model().get_name());
        assertEquals(convo1.get_msgs_len(), result1.get_msgs_len());
        for (int i = 0; i < convo1.get_msgs_len(); i++) {
            assertEquals(convo1.get_role(i), result1.get_role(i));
            assertEquals(convo1.get_msg(i), result1.get_msg(i));
        }
        assertEquals(convo1.get_addrs().length, result1.get_addrs().length);
        for (int i = 0; i < convo1.get_addrs().length; i++) {
            assertEquals(convo1.get_addrs()[i], result1.get_addrs()[i]);
        }

        Conversation result2 = container.get_convo(convo2.get_uuid());
        assertEquals(convo2.get_model().get_name(), result2.get_model().get_name());
        assertEquals(convo2.get_msgs_len(), result2.get_msgs_len());
        for (int i = 0; i < convo2.get_msgs_len(); i++) {
            assertEquals(convo2.get_role(i), result2.get_role(i));
            assertEquals(convo2.get_msg(i), result2.get_msg(i));
        }
        assertEquals(convo2.get_addrs().length, result2.get_addrs().length);
        for (int i = 0; i < convo2.get_addrs().length; i++) {
            assertEquals(convo2.get_addrs()[i], result2.get_addrs()[i]);
        }
    }
}
