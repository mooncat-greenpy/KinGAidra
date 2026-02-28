package kingaidra.keyfunc;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerDummy;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelConfSingle;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.ghidra.PromptConf;
import kingaidra.testutil.ChatModelPreferencesDummy;
import kingaidra.testutil.GhidraTestUtil;
import kingaidra.testutil.ModelDummy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

public class GuessTest {
    @Test
    void test_constructor() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ModelDummy("Dummy", "dummy.py", true));
        ModelConfSingle model_conf = new ModelConfSingle("keyfunc", pref);
        Guess guess = new Guess(gu, ai, model_conf, conf);
        assertTrue(model_conf.exist_model("Dummy"));
        assertFalse(model_conf.exist_model("Dummy1"));
        assertEquals(model_conf.get_model_script("Dummy"), "dummy.py");
        assertEquals(model_conf.get_models_len(), 1);
        assertEquals(model_conf.get_models()[0], "Dummy");
        assertEquals(model_conf.get_model_status(model_conf.get_models()[0]), true);
        // Not suppoort
        // assertEquals(model_conf.get_model_status(new ModelDummy("Dummy", "dummy.py", true)), false);
    }

    @Test
    void test_set_model_name_script() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ModelDummy("Dummy", "dummy.py", true));
        ModelConfSingle model_conf = new ModelConfSingle("keyfunc", pref);
        Guess guess = new Guess(gu, ai, model_conf, conf);
        model_conf.set_model_name("Dummy", "d");
        model_conf.set_model_script("d", "d.py");
        assertTrue(model_conf.exist_model("d"));
        assertFalse(model_conf.exist_model("Dummy"));
        assertEquals(model_conf.get_model_script("d"), "d.py");
    }

    @Test
    void test_set_model_status() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref1 = new ChatModelPreferencesDummy();
        pref1.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", true));
        pref1.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", true));
        pref1.store("Dummy3", new ModelDummy("Dummy3", "dummy.py", true));
        ModelConfSingle model_conf1 = new ModelConfSingle("keyfunc", pref1);
        Guess guess1 = new Guess(gu, ai, model_conf1, conf);
        assertEquals(model_conf1.get_model_status("Dummy1"), true);
        assertEquals(model_conf1.get_model_status("Dummy2"), false);
        assertEquals(model_conf1.get_model_status("Dummy3"), false);
        model_conf1.set_model_status("Dummy1", true);
        assertEquals(model_conf1.get_model_status("Dummy1"), true);
        assertEquals(model_conf1.get_model_status("Dummy2"), false);
        assertEquals(model_conf1.get_model_status("Dummy3"), false);
        model_conf1.set_model_status("Dummy1", false);
        assertEquals(model_conf1.get_model_status("Dummy1"), true);
        assertEquals(model_conf1.get_model_status("Dummy2"), false);
        assertEquals(model_conf1.get_model_status("Dummy3"), false);

        GhidraPreferences<Model> pref2 = new ChatModelPreferencesDummy();
        pref2.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", false));
        pref2.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", false));
        pref2.store("Dummy3", new ModelDummy("Dummy3", "dummy.py", false));
        ModelConfSingle model_conf2 = new ModelConfSingle("keyfunc", pref2);
        Guess guess2 = new Guess(gu, ai, model_conf2, conf);
        assertEquals(model_conf2.get_model_status("Dummy1"), true);
        assertEquals(model_conf2.get_model_status("Dummy2"), false);
        assertEquals(model_conf2.get_model_status("Dummy3"), false);
    }

    @Test
    void test_guess_by_chat_histories() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", false));
        pref.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", true));
        pref.store("Dummy3", new ModelDummy("Dummy3", "dummy.py", false));
        ModelConfSingle model_conf = new ModelConfSingle("keyfunc", pref);
        Guess guess = new Guess(gu, ai, model_conf, conf);

        Map.Entry<Function, String>[] funcs = guess.guess_by_chat_histories(util.get_addr(program, 0x401000));
        assertTrue(funcs.length >= 2);
        boolean has_malware_401 = false;
        boolean has_malware_404 = false;
        for (Map.Entry<Function, String> entry : funcs) {
            if (entry.getKey().getName().equals("func_401000")
                    && entry.getValue().contains("entry flow and dispatch")) {
                has_malware_401 = true;
            }
            if (entry.getKey().getName().equals("func_404000")
                    && entry.getValue().contains("C2 communication")) {
                has_malware_404 = true;
            }
        }
        assertTrue(has_malware_401);
        assertTrue(has_malware_404);
    }
}
