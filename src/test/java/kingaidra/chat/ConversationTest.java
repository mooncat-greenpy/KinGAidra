package kingaidra.chat;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ConversationTest {
    @Test
    void test_constructor() {
        Conversation conv = new Conversation(null);
        assertEquals(conv.get_model(), null);
        assertEquals(conv.get_msg(0), null);
        assertEquals(conv.get_msgs_len(), 0);
    }

    @Test
    void test_add_msg() {
        Conversation conv = new Conversation(null);
        assertFalse(conv.add_assistant_msg("assistant_test1"));
        assertEquals(conv.get_msgs_len(), 0);

        assertTrue(conv.add_user_msg("user_test1"));
        assertEquals(conv.get_msg(0), "user_test1");
        assertEquals(conv.get_msgs_len(), 1);

        assertFalse(conv.add_system_msg("system_test2"));
        assertEquals(conv.get_msgs_len(), 1);
        assertFalse(conv.add_user_msg("user_test2"));
        assertEquals(conv.get_msgs_len(), 1);

        assertTrue(conv.add_assistant_msg("assistant_test2"));
        assertEquals(conv.get_msg(1), "assistant_test2");
        assertEquals(conv.get_msgs_len(), 2);

        assertFalse(conv.add_system_msg("system_test3"));
        assertEquals(conv.get_msgs_len(), 2);
        assertFalse(conv.add_assistant_msg("assistant_test3"));
        assertEquals(conv.get_msgs_len(), 2);

        assertTrue(conv.add_user_msg("user_test3"));
        assertEquals(conv.get_msg(2), "user_test3");
        assertEquals(conv.get_msgs_len(), 3);

        Conversation conv2 = new Conversation(null);
        assertTrue(conv2.add_system_msg("system_test1"));
        assertEquals(conv2.get_msg(0), "system_test1");
        assertEquals(conv2.get_msgs_len(), 1);

        assertFalse(conv2.add_system_msg("system_test2"));
        assertEquals(conv2.get_msgs_len(), 1);
        assertFalse(conv2.add_assistant_msg("assistant_test2"));
        assertEquals(conv2.get_msgs_len(), 1);

        assertTrue(conv2.add_user_msg("user_test2"));
        assertEquals(conv2.get_msg(1), "user_test2");
        assertEquals(conv2.get_msgs_len(), 2);
    }
}
