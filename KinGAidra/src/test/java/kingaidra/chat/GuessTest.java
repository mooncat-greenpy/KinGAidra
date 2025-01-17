package kingaidra.chat;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerDummy;
import kingaidra.ai.model.Model;
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
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(null, program, gu, container, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ChatModelDummy("Dummy", "dummy.py", true));
        Guess guess = new Guess(ai, pref);
        assertTrue(guess.exist_model("Dummy"));
        assertFalse(guess.exist_model("Dummy1"));
        assertEquals(guess.get_model_script("Dummy"), "dummy.py");
        assertEquals(guess.get_models_len(), 1);
        assertEquals(guess.get_models()[0], "Dummy");
        assertEquals(guess.get_model_status(guess.get_models()[0]), true);
        // Not suppoort
        // assertEquals(guess.get_model_status(new ChatModelDummy("Dummy", "dummy.py", true)),
        // false);
    }

    @Test
    void test_set_model_name_script() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(null, program, gu, container, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ChatModelDummy("Dummy", "dummy.py", true));
        Guess guess = new Guess(ai, pref);
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
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(null, program, gu, container, null);
        GhidraPreferences<Model> pref1 = new ChatModelPreferencesDummy();
        pref1.store("Dummy1", new ChatModelDummy("Dummy1", "dummy.py", true));
        pref1.store("Dummy2", new ChatModelDummy("Dummy2", "dummy.py", true));
        pref1.store("Dummy3", new ChatModelDummy("Dummy3", "dummy.py", true));
        Guess guess1 = new Guess(ai, pref1);
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
        Guess guess2 = new Guess(ai, pref2);
        assertEquals(guess2.get_model_status("Dummy1"), true);
        assertEquals(guess2.get_model_status("Dummy2"), false);
        assertEquals(guess2.get_model_status("Dummy3"), false);
    }

    @Test
    void test_guess() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(null, program, gu, container, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy1", new ChatModelDummy("Dummy1", "dummy.py", false));
        pref.store("Dummy2", new ChatModelDummy("Dummy2", "dummy.py", true));
        pref.store("Dummy3", new ChatModelDummy("Dummy3", "dummy.py", false));
        Guess guess = new Guess(ai, pref);
        Conversation convo1 = guess.guess("msg", util.get_addr(program, 0x402000));
        assertEquals(convo1.get_msgs_len(), 2);
        assertEquals(convo1.get_msg(0), "msg");
        assertEquals(convo1.get_msg(1), "msgDummy2");
        assertEquals(convo1.get_addrs().length, 0);
        guess.guess(convo1, "Explain\n<code>", util.get_addr(program, 0x402000));
        assertEquals(convo1.get_msgs_len(), 4);
        assertEquals(convo1.get_msg(0), "msg");
        assertEquals(convo1.get_msg(1), "msgDummy2");
        assertTrue(convo1.get_msg(2).contains("int __fastcall func_402000(undefined *param_1)"));
        assertTrue(convo1.get_msg(3).endsWith("Dummy2"));
        assertEquals(convo1.get_addrs().length, 1);
        assertEquals(convo1.get_addrs()[0].getOffset(), 0x402000);

        Conversation convo2 = guess.guess("msg", util.get_addr(program, 0x401000));
        guess.guess(convo2, "Explain\n<asm>", util.get_addr(program, 0x401000));
        assertEquals(convo2.get_msgs_len(), 4);
        assertEquals(convo2.get_msg(0), "msg");
        assertEquals(convo2.get_msg(1), "msgDummy2");
        assertTrue(convo2.get_msg(2)
                .contains("func_401000:\n    PUSH EBP\n    MOV EBP,ESP\n    POP EBP\n    RET\n"));
        assertTrue(convo2.get_msg(3).endsWith("Dummy2"));
        assertEquals(convo2.get_addrs().length, 1);
        assertEquals(convo2.get_addrs()[0].getOffset(), 0x401000);

        Conversation convo3 = guess.guess("msg", util.get_addr(program, 0x408000));
        guess.guess(convo3, "Explain\n<calltree>", util.get_addr(program, 0x408000));
        assertEquals(convo3.get_msgs_len(), 4);
        assertEquals(convo3.get_msg(0), "msg");
        assertEquals(convo3.get_msg(1), "msgDummy2");
        assertTrue(convo3.get_msg(2).contains("- func_408000\n" +
                                "    - func_407000\n"));
        assertTrue(convo3.get_msg(3).endsWith("Dummy2"));
        assertEquals(convo3.get_addrs().length, 1);
        assertEquals(convo3.get_addrs()[0].getOffset(), 0x408000);
    }
}
