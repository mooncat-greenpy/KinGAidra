package kingaidra.ai.convo;

import org.junit.jupiter.api.Test;
import kingaidra.ai.convo.Conversation;
import kingaidra.testutil.ModelDummy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ConversationTest {
    @Test
    void test_constructor() {
        Conversation conv = new Conversation(ConversationType.SYSTEM, new ModelDummy("Dummy", "dummy.py", true));
        assertEquals(conv.get_type(), ConversationType.SYSTEM);
        assertEquals(conv.get_model().get_name(), "Dummy");
        assertEquals(conv.get_msg(0), null);
        assertEquals(conv.get_msgs_len(), 0);
        assertEquals(conv.get_created(), conv.get_updated());

        assertEquals(new Conversation(ConversationType.USER, null).get_type(), ConversationType.USER);
    }

    @Test
    void test_add_msg() {
        Conversation conv = new Conversation(ConversationType.SYSTEM, null);
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

        Conversation conv2 = new Conversation(ConversationType.SYSTEM, null);
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
}
