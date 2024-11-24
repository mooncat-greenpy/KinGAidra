package kingaidra.decom;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.ai.Model;
import kingaidra.decom.ai.Ai;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
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
        Ai ai = new Ai(null, program, gu, null);
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
        Ai ai = new Ai(null, program, gu, null);
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
        Ai ai = new Ai(null, program, gu, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ModelDummy("Dummy", "dummy.py", true));
        Guess guess = new Guess(gu, ai, pref);
        guess.set_model_status(guess.get_models()[0], false);
        assertEquals(guess.get_model_status(guess.get_models()[0]), false);
        guess.set_model_status(guess.get_models()[0], true);
        assertEquals(guess.get_model_status(guess.get_models()[0]), true);
    }

    @Test
    void test_guess() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Ai ai = new Ai(null, program, gu, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ModelDummy("Dummy", "dummy.py", true));
        Guess guess = new Guess(gu, ai, pref);
        DecomDiff diff = guess.guess(guess.get_models()[0], util.get_addr(program, 0x402000));
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
    }


    @Test
    void test_guess_all() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Ai ai = new Ai(null, program, gu, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", true));
        pref.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", true));
        Guess guess = new Guess(gu, ai, pref);
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
        Ai ai = new Ai(null, program, gu, null);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", true));
        pref.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", true));
        Guess guess = new Guess(gu, ai, pref);
        guess.set_model_status(guess.get_models()[1], false);
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
