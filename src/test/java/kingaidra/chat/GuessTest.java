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

public class GuessTest {
    @Test
    void test_constructor() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Ai ai = new Ai(null, program, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ChatModelDummy("Dummy", "dummy.py", true));
        Guess guess = new Guess(gu, ai, pref);
        assertTrue(guess.exist_model("Dummy"));
        assertFalse(guess.exist_model("Dummy1"));
        assertEquals(guess.get_model_script("Dummy"), "dummy.py");
        assertEquals(guess.get_models_len(), 1);
        assertEquals(guess.get_models()[0], "Dummy");
        assertEquals(guess.get_model_status(guess.get_models()[0]), true);
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
        Guess guess = new Guess(gu, ai, pref);
        guess.set_model_name("Dummy", "d");
        guess.set_model_script("d", "d.py");
        assertTrue(guess.exist_model("d"));
        assertFalse(guess.exist_model("Dummy"));
        assertEquals(guess.get_model_script("d"), "d.py");
    }

    @Test
    void test_set_model_status() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Ai ai = new Ai(null, program, null);
        GhidraPreferences<Model> pref1 = new ChatModelPreferencesDummy();
        pref1.store("Dummy1", new ChatModelDummy("Dummy1", "dummy.py", true));
        pref1.store("Dummy2", new ChatModelDummy("Dummy2", "dummy.py", true));
        pref1.store("Dummy3", new ChatModelDummy("Dummy3", "dummy.py", true));
        Guess guess1 = new Guess(gu, ai, pref1);
        assertEquals(guess1.get_model_status("Dummy1"), true);
        assertEquals(guess1.get_model_status("Dummy2"), false);
        assertEquals(guess1.get_model_status("Dummy3"), false);
        guess1.set_model_status("Dummy1", true);
        assertEquals(guess1.get_model_status("Dummy1"), true);
        assertEquals(guess1.get_model_status("Dummy2"), false);
        assertEquals(guess1.get_model_status("Dummy3"), false);
        guess1.set_model_status("Dummy1", false);
        assertEquals(guess1.get_model_status("Dummy1"), true);
        assertEquals(guess1.get_model_status("Dummy2"), false);
        assertEquals(guess1.get_model_status("Dummy3"), false);

        GhidraPreferences<Model> pref2 = new ChatModelPreferencesDummy();
        pref2.store("Dummy1", new ChatModelDummy("Dummy1", "dummy.py", false));
        pref2.store("Dummy2", new ChatModelDummy("Dummy2", "dummy.py", false));
        pref2.store("Dummy3", new ChatModelDummy("Dummy3", "dummy.py", false));
        Guess guess2 = new Guess(gu, ai, pref2);
        assertEquals(guess2.get_model_status("Dummy1"), true);
        assertEquals(guess2.get_model_status("Dummy2"), false);
        assertEquals(guess2.get_model_status("Dummy3"), false);
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
        Guess guess = new Guess(gu, ai, pref);
        Conversation convo =
                guess.guess("msg", util.get_addr(program, 0x402000));
        assertEquals(convo.get_msgs_len(), 2);
        assertEquals(convo.get_msg(0), "msg");
        assertEquals(convo.get_msg(1), "msgDummy2");
        guess.guess(convo, "Explain\n<code>", util.get_addr(program, 0x402000));
        assertEquals(convo.get_msgs_len(), 4);
        assertEquals(convo.get_msg(0), "msg");
        assertEquals(convo.get_msg(1), "msgDummy2");
        assertTrue(convo.get_msg(2).contains("int __fastcall func_402000(undefined *param_1)"));
        assertTrue(convo.get_msg(3).endsWith("Dummy2"));
    }
}
