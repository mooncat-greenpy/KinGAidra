package kingaidra.decom;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerDummy;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelConfMultiple;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.ghidra.PromptConf;
import kingaidra.testutil.GhidraTestUtil;
import kingaidra.testutil.ModelDummy;
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
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ModelDummy("Dummy", "dummy.py", true));
        ModelConfMultiple model_conf = new ModelConfMultiple("decom", pref);
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
        ModelConfMultiple model_conf = new ModelConfMultiple("decom", pref);
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
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ModelDummy("Dummy", "dummy.py", true));
        ModelConfMultiple model_conf = new ModelConfMultiple("decom", pref);
        Guess guess = new Guess(gu, ai, model_conf, conf);
        model_conf.set_model_status(model_conf.get_models()[0], false);
        assertEquals(model_conf.get_model_status(model_conf.get_models()[0]), false);
        model_conf.set_model_status(model_conf.get_models()[0], true);
        assertEquals(model_conf.get_model_status(model_conf.get_models()[0]), true);
    }

    @Test
    void test_guess() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ModelDummy("Dummy", "dummy.py", true));
        ModelConfMultiple model_conf = new ModelConfMultiple("decom", pref);
        Guess guess = new Guess(gu, ai, model_conf, conf);
        DecomDiff diff = guess.guess(guess.get_model_conf().get_models()[0], util.get_addr(program, 0x402000), false);
        assertEquals(diff.get_name().get_new_name(), "func_402000Dummy");
        for (DiffPair pair : diff.get_params()) {
            assertEquals(pair.get_new_name().substring(pair.get_new_name().length() - 5), "Dummy");
        }
        for (DiffPair pair : diff.get_vars()) {
            assertEquals(pair.get_new_name().substring(pair.get_new_name().length() - 5), "Dummy");
        }
        for (DiffPair pair : diff.get_datatypes()) {
            assertEquals(pair.get_new_name().substring(pair.get_new_name().length() - 5), "Dummy");
        }

        Conversation convo = container.get_convo(container.get_ids()[0]);
        assertEquals(convo.get_type(), ConversationType.SYSTEM_DECOM);
    }


    @Test
    void test_guess_all() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", true));
        pref.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", true));
        ModelConfMultiple model_conf = new ModelConfMultiple("decom", pref);
        Guess guess = new Guess(gu, ai, model_conf, conf);
        DecomDiff[] diffs = guess.guess_all(util.get_addr(program, 0x402000));

        for (DecomDiff diff : diffs) {
            assertEquals(diff.get_name().get_new_name(),
                    "func_402000" + diff.get_model().get_name());
            for (DiffPair pair : diff.get_params()) {
                assertEquals(
                        pair.get_new_name()
                                .substring(pair.get_new_name().length()
                                        - diff.get_model().get_name().length()),
                        diff.get_model().get_name());
            }
            for (DiffPair pair : diff.get_vars()) {
                assertEquals(
                        pair.get_new_name()
                                .substring(pair.get_new_name().length()
                                        - diff.get_model().get_name().length()),
                        diff.get_model().get_name());
            }
            for (DiffPair pair : diff.get_datatypes()) {
                assertEquals(
                        pair.get_new_name()
                                .substring(pair.get_new_name().length()
                                        - diff.get_model().get_name().length()),
                        diff.get_model().get_name());
            }
        }
    }

    void test_guess_selected() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", true));
        pref.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", true));
        ModelConfMultiple model_conf = new ModelConfMultiple("decom", pref);
        Guess guess = new Guess(gu, ai, model_conf, conf);
        guess.get_model_conf().set_model_status(guess.get_model_conf().get_models()[1], false);
        DecomDiff[] diffs = guess.guess_selected(util.get_addr(program, 0x402000));
        assertEquals(diffs.length, 1);
        DecomDiff diff = diffs[0];

        assertEquals(diff.get_name().get_new_name(), "func_402000" + "Dummy1");
        for (DiffPair pair : diff.get_params()) {
            assertEquals(
                    pair.get_new_name().substring(
                            pair.get_new_name().length() - diff.get_model().get_name().length()),
                    "Dummy1");
        }
        for (DiffPair pair : diff.get_vars()) {
            assertEquals(
                    pair.get_new_name().substring(
                            pair.get_new_name().length() - diff.get_model().get_name().length()),
                    "Dummy1");
        }
        for (DiffPair pair : diff.get_datatypes()) {
            assertEquals(
                    pair.get_new_name().substring(
                            pair.get_new_name().length() - diff.get_model().get_name().length()),
                    "Dummy1");
        }
    }
}
