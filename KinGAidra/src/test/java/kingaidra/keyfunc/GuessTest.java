package kingaidra.keyfunc;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerDummy;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelConfSingle;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
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
        ModelConfSingle model_conf = new ModelConfSingle("keyfunc", pref);
        Guess guess = new Guess(gu, ai, model_conf);
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
        Ai ai = new Ai(null, program, gu, container, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ModelDummy("Dummy", "dummy.py", true));
        ModelConfSingle model_conf = new ModelConfSingle("keyfunc", pref);
        Guess guess = new Guess(gu, ai, model_conf);
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
        Ai ai = new Ai(null, program, gu, container, null);
        GhidraPreferences<Model> pref1 = new ChatModelPreferencesDummy();
        pref1.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", true));
        pref1.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", true));
        pref1.store("Dummy3", new ModelDummy("Dummy3", "dummy.py", true));
        ModelConfSingle model_conf1 = new ModelConfSingle("keyfunc", pref1);
        Guess guess1 = new Guess(gu, ai, model_conf1);
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
        Guess guess2 = new Guess(gu, ai, model_conf2);
        assertEquals(model_conf2.get_model_status("Dummy1"), true);
        assertEquals(model_conf2.get_model_status("Dummy2"), false);
        assertEquals(model_conf2.get_model_status("Dummy3"), false);
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
        ModelConfSingle model_conf = new ModelConfSingle("keyfunc", pref);
        Guess guess = new Guess(gu, ai, model_conf);
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

        Conversation convo = container.get_convo(container.get_ids()[0]);
        assertEquals(convo.get_type(), ConversationType.SYSTEM_KEYFUNC);
    }

    @Test
    void test_guess_by_strings() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(null, program, gu, container, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", false));
        pref.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", true));
        pref.store("Dummy3", new ModelDummy("Dummy3", "dummy.py", false));
        ModelConfSingle model_conf = new ModelConfSingle("keyfunc", pref);
        Guess guess = new Guess(gu, ai, model_conf);
        String[] strings = guess.guess_by_strings();
        assertEquals(strings.length, 4);
        assertEquals(strings[0], "string1");
        assertEquals(strings[1], "string2");
        assertEquals(strings[2], "string3");
        assertEquals(strings[3], "ing2");
        Data[] data = guess.guess_string_data();
        assertEquals(data.length, 3);
        assertEquals(data[0].getAddress(), util.get_addr(program, 0x40f000));
        assertEquals(data[0].getValue(), "string1");
        assertEquals(data[1].getAddress(), util.get_addr(program, 0x40f100));
        assertEquals(data[1].getValue(), "string2");
        assertEquals(data[2].getAddress(), util.get_addr(program, 0x40f200));
        assertEquals(data[2].getValue(), "string3");

        Conversation convo = container.get_convo(container.get_ids()[0]);
        assertEquals(convo.get_type(), ConversationType.USER_CHAT);
    }
}
