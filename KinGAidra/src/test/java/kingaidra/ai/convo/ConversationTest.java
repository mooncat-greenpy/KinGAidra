package kingaidra.ai.convo;

import org.junit.jupiter.api.Test;

import ghidra.program.model.address.Address;
import kingaidra.ai.convo.Message;
import kingaidra.testutil.ModelDummy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ConversationTest {
    @Test
    void test_constructor() {
        Conversation conv = new Conversation(ConversationType.SYSTEM_DECOM, new ModelDummy("Dummy", "dummy.py", true));
        assertEquals(conv.get_type(), ConversationType.SYSTEM_DECOM);
        assertEquals(conv.get_model().get_name(), "Dummy");
        assertEquals(conv.get_msg(0), null);
        assertEquals(conv.get_msgs_len(), 0);
        assertEquals(conv.get_created(), conv.get_updated());

        assertEquals(new Conversation(ConversationType.USER_CHAT, null).get_type(), ConversationType.USER_CHAT);
    }

    @Test
    void test_add_msg() {
        Conversation conv = new Conversation(ConversationType.SYSTEM_DECOM, null);
        assertFalse(conv.add_assistant_msg("assistant_test1"));
        assertEquals(conv.get_msgs_len(), 0);
        String created = conv.get_created();
        String updated = conv.get_updated();
        try {
            Thread.sleep(1000);
        } catch(Exception e) {
        }

        assertTrue(conv.add_user_msg("user_test1"));
        assertEquals(conv.get_role(0), "user");
        assertEquals(conv.get_msg(0), "user_test1");
        assertEquals(conv.get_msgs_len(), 1);
        assertEquals(conv.get_created(), created);
        assertFalse(conv.get_updated().equals(updated));
        created = conv.get_created();
        updated = conv.get_updated();
        try {
            Thread.sleep(1000);
        } catch(Exception e) {
        }

        assertFalse(conv.add_system_msg("system_test2"));
        assertEquals(conv.get_msgs_len(), 1);
        assertFalse(conv.add_user_msg("user_test2"));
        assertEquals(conv.get_msgs_len(), 1);
        assertEquals(conv.get_created(), created);
        assertEquals(conv.get_updated(), updated);

        assertTrue(conv.add_assistant_msg("assistant_test2"));
        assertEquals(conv.get_role(1), "assistant");
        assertEquals(conv.get_msg(1), "assistant_test2");
        assertEquals(conv.get_msgs_len(), 2);
        assertEquals(conv.get_created(), created);
        assertFalse(conv.get_updated().equals(updated));
        created = conv.get_created();
        updated = conv.get_updated();
        try {
            Thread.sleep(1000);
        } catch(Exception e) {
        }

        assertFalse(conv.add_system_msg("system_test3"));
        assertEquals(conv.get_msgs_len(), 2);
        assertFalse(conv.add_assistant_msg("assistant_test3"));
        assertEquals(conv.get_msgs_len(), 2);
        assertEquals(conv.get_created(), created);
        assertEquals(conv.get_updated(), updated);

        assertTrue(conv.add_user_msg("user_test3"));
        assertEquals(conv.get_role(2), "user");
        assertEquals(conv.get_msg(2), "user_test3");
        assertEquals(conv.get_msgs_len(), 3);
        assertEquals(conv.get_created(), created);
        assertFalse(conv.get_updated().equals(updated));

        Conversation conv2 = new Conversation(ConversationType.SYSTEM_DECOM, null);
        assertTrue(conv2.add_system_msg("system_test1"));
        assertEquals(conv2.get_role(0), "system");
        assertEquals(conv2.get_msg(0), "system_test1");
        assertEquals(conv2.get_msgs_len(), 1);

        assertFalse(conv2.add_system_msg("system_test2"));
        assertEquals(conv2.get_msgs_len(), 1);
        assertFalse(conv2.add_assistant_msg("assistant_test2"));
        assertEquals(conv2.get_msgs_len(), 1);

        assertTrue(conv2.add_user_msg("user_test2"));
        assertEquals(conv2.get_role(1), "user");
        assertEquals(conv2.get_msg(1), "user_test2");
        assertEquals(conv2.get_msgs_len(), 2);
    }

    @Test
    void test_tool_and_raw_messages() {
        Conversation conv = new Conversation(ConversationType.USER_CHAT, null);
        assertTrue(conv.add_msg(Conversation.TOOL_ROLE, "tool_result_1"));
        assertEquals(Conversation.TOOL_ROLE, conv.get_role(0));
        assertEquals("tool_result_1", conv.get_msg(0));
        assertEquals(1, conv.get_msgs_len());

        assertTrue(conv.add_msg(Conversation.USER_ROLE, "user_test"));
        assertEquals(Conversation.USER_ROLE, conv.get_role(1));
        assertEquals("user_test", conv.get_msg(1));
        assertEquals(2, conv.get_msgs_len());

        assertTrue(conv.add_raw_msg(Conversation.ASSISTANT_ROLE, "assistant_raw"));
        assertEquals(Conversation.ASSISTANT_ROLE, conv.get_role(2));
        assertEquals("assistant_raw", conv.get_msg(2));
        assertEquals(3, conv.get_msgs_len());

        assertFalse(conv.add_msg("unknown", "bad"));
        assertEquals(3, conv.get_msgs_len());
    }

    @Test
    void test_constructor_preserves_tool_role() {
        Message[] msgs = new Message[] {
                new Message(Conversation.SYSTEM_ROLE, "sys"),
                new Message(Conversation.USER_ROLE, "user"),
                new Message(Conversation.TOOL_ROLE, "tool"),
                new Message(Conversation.ASSISTANT_ROLE, "assistant")
        };
        Conversation conv = new Conversation(
                "00000000-0000-0000-0000-000000000001",
                ConversationType.USER_CHAT,
                new ModelDummy("Dummy", "dummy.py", true),
                "2024-01-01 00:00:00",
                "2024-01-01 00:00:00",
                msgs,
                new Address[] {});
        assertEquals(4, conv.get_msgs_len());
        assertEquals(Conversation.SYSTEM_ROLE, conv.get_role(0));
        assertEquals(Conversation.USER_ROLE, conv.get_role(1));
        assertEquals(Conversation.TOOL_ROLE, conv.get_role(2));
        assertEquals(Conversation.ASSISTANT_ROLE, conv.get_role(3));
        assertEquals("tool", conv.get_msg(2));

        Message[] new_msgs = new Message[] {
                new Message(Conversation.SYSTEM_ROLE, "sys"),
                new Message(Conversation.USER_ROLE, "user"),
                new Message(Conversation.TOOL_ROLE, "tool", "call-1", null),
                new Message(Conversation.ASSISTANT_ROLE, "assistant")
        };
        Conversation conv2 = new Conversation(
                "00000000-0000-0000-0000-000000000001",
                ConversationType.USER_CHAT,
                new ModelDummy("Dummy", "dummy.py", true),
                "2024-01-01 00:00:00",
                "2024-01-01 00:00:00",
                new_msgs,
                new Address[] {});
        assertEquals("call-1", conv2.get_tool_call_id(2));
    }
}
