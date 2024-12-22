package kingaidra.keyfunc;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Function;
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
import kingaidra.testutil.ChatModelDummy;
import kingaidra.testutil.ChatModelPreferencesDummy;
import kingaidra.testutil.GhidraTestUtil;
import kingaidra.testutil.ModelDummy;

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
        pref.store("Dummy", new ModelDummy("Dummy", "dummy.py", true));
        Guess guess = new Guess(gu, ai, pref);
        assertTrue(guess.exist_model("Dummy"));
        assertFalse(guess.exist_model("Dummy1"));
        assertEquals(guess.get_model_script("Dummy"), "dummy.py");
        assertEquals(guess.get_models_len(), 1);
        assertEquals(guess.get_models()[0], "Dummy");
        assertEquals(guess.get_model_status(guess.get_models()[0]), true);
        // Not suppoort
        // assertEquals(guess.get_model_status(new ModelDummy("Dummy", "dummy.py", true)), false);
    }

    @Test
    void test_set_model_name_script() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(null, program, gu, container, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ModelDummy("Dummy", "dummy.py", true));
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
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(null, program, gu, container, null);
        GhidraPreferences<Model> pref1 = new ChatModelPreferencesDummy();
        pref1.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", true));
        pref1.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", true));
        pref1.store("Dummy3", new ModelDummy("Dummy3", "dummy.py", true));
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
        pref2.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", false));
        pref2.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", false));
        pref2.store("Dummy3", new ModelDummy("Dummy3", "dummy.py", false));
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
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(null, program, gu, container, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", false));
        pref.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", true));
        pref.store("Dummy3", new ModelDummy("Dummy3", "dummy.py", false));
        Guess guess = new Guess(gu, ai, pref);
        Function[] funcs = guess.guess("- func_404000\n" +
                                "    - func_403000\n" +
                                "        - func_401000\n" +
                                "        - func_402000\n" +
                                "    - func_405000\n" +
                                "- func_406000\n" +
                                "    - func_405000\n" +
                                "        - func_402000\n" +
                                "- func_408000\n" +
                                "    - func_407000\n", null);
        assertEquals(funcs.length, 3);
        assertEquals(funcs[0].getEntryPoint().getOffset(), 0x401000);
        assertEquals(funcs[0].getName(), "func_401000");
        assertEquals(funcs[1].getEntryPoint().getOffset(), 0x404000);
        assertEquals(funcs[1].getName(), "func_404000");
        assertEquals(funcs[2].getEntryPoint().getOffset(), 0x406000);
        assertEquals(funcs[2].getName(), "func_406000");
    }
}
