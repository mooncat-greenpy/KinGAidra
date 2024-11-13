package kingaidra.chat;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.chat.ai.Ai;
import kingaidra.chat.ai.Model;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.testutil.GhidraTestUtil;
import kingaidra.testutil.ChatModelDummy;
import kingaidra.testutil.ChatModelPreferencesDummy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ChatTest {
    @Test
    void test_constructor() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Ai ai = new Ai(null, program, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ChatModelDummy("Dummy", "dummy.py", true));
        Chat chat = new Chat(gu, ai, pref);
        assertTrue(chat.exist_model("Dummy"));
        assertFalse(chat.exist_model("Dummy1"));
        assertEquals(chat.get_model_script("Dummy"), "dummy.py");
        assertEquals(chat.get_models_len(), 1);
        assertEquals(chat.get_models()[0], "Dummy");
        assertEquals(chat.get_model_status(chat.get_models()[0]), true);
        // Not suppoort
        // assertEquals(guess.get_model_status(new ChatModelDummy("Dummy", "dummy.py", true)), false);
    }

    @Test
    void test_set_model_name_script() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Ai ai = new Ai(null, program, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ChatModelDummy("Dummy", "dummy.py", true));
        Chat chat = new Chat(gu, ai, pref);
        chat.set_model_name("Dummy", "d");
        chat.set_model_script("d", "d.py");
        assertTrue(chat.exist_model("d"));
        assertFalse(chat.exist_model("Dummy"));
        assertEquals(chat.get_model_script("d"), "d.py");
    }

    @Test
    void test_set_model_status() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Ai ai = new Ai(null, program, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy1", new ChatModelDummy("Dummy1", "dummy.py", true));
        pref.store("Dummy2", new ChatModelDummy("Dummy2", "dummy.py", true));
        pref.store("Dummy3", new ChatModelDummy("Dummy3", "dummy.py", true));
        Chat chat = new Chat(gu, ai, pref);
        assertEquals(chat.get_model_status("Dummy1"), true);
        assertEquals(chat.get_model_status("Dummy2"), false);
        assertEquals(chat.get_model_status("Dummy3"), false);
        chat.set_model_status("Dummy1", true);
        assertEquals(chat.get_model_status("Dummy1"), true);
        assertEquals(chat.get_model_status("Dummy2"), false);
        assertEquals(chat.get_model_status("Dummy3"), false);
        chat.set_model_status("Dummy1", false);
        assertEquals(chat.get_model_status("Dummy1"), true);
        assertEquals(chat.get_model_status("Dummy2"), false);
        assertEquals(chat.get_model_status("Dummy3"), false);

        GhidraPreferences<Model> pref1 = new ChatModelPreferencesDummy();
        pref1.store("Dummy1", new ChatModelDummy("Dummy1", "dummy.py", false));
        pref1.store("Dummy2", new ChatModelDummy("Dummy2", "dummy.py", false));
        pref1.store("Dummy3", new ChatModelDummy("Dummy3", "dummy.py", false));
        Chat chat1 = new Chat(gu, ai, pref1);
        assertEquals(chat1.get_model_status("Dummy1"), true);
        assertEquals(chat1.get_model_status("Dummy2"), false);
        assertEquals(chat1.get_model_status("Dummy3"), false);
    }

    @Test
    void test_guess() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Ai ai = new Ai(null, program, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy1", new ChatModelDummy("Dummy1", "dummy.py", false));
        pref.store("Dummy2", new ChatModelDummy("Dummy2", "dummy.py", true));
        pref.store("Dummy3", new ChatModelDummy("Dummy3", "dummy.py", false));
        Chat chat = new Chat(gu, ai, pref);
        Conversation convo =
                chat.guess("msg", util.get_addr(program, 0x402000));
        assertEquals(convo.get_msgs_len(), 2);
        assertEquals(convo.get_msg(0), "msg");
        assertEquals(convo.get_msg(1), "msgDummy2");
        chat.guess(convo, "Explain\n<code>", util.get_addr(program, 0x402000));
        assertEquals(convo.get_msgs_len(), 4);
        assertEquals(convo.get_msg(0), "msg");
        assertEquals(convo.get_msg(1), "msgDummy2");
        assertTrue(convo.get_msg(2).contains("int __fastcall func_402000(undefined *param_1)"));
        assertTrue(convo.get_msg(3).endsWith("Dummy2"));
    }
}
