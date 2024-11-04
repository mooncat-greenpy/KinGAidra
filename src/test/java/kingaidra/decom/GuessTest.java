package kingaidra.decom;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.decom.ai.Ai;
import kingaidra.decom.ai.Model;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.testutil.GhidraTestUtil;
import kingaidra.testutil.ModelDummy;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class GuessTest {
    @Test
    void test_constructor() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Ai ai = new Ai(null, program, null);
        Guess guess = new Guess(gu, ai, new Model[] {new ModelDummy("Dummy", "dummy.py")});
        assertEquals(guess.get_models_len(), 1);
        assertEquals(guess.get_models()[0].get_name(), "Dummy");
        assertEquals(guess.get_model_status(guess.get_models()[0]), true);
        // Not suppoort
        // assertEquals(guess.get_model_status(new ModelDummy("Dummy", "dummy.py")), false);
    }

    @Test
    void test_set_model_status() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Ai ai = new Ai(null, program, null);
        Guess guess = new Guess(gu, ai, new Model[] {new ModelDummy("Dummy", "dummy.py")});
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
        Ai ai = new Ai(null, program, null);
        Guess guess = new Guess(gu, ai, new Model[] {new ModelDummy("Dummy", "dummy.py")});
        DecomDiff diff = guess.guess(guess.get_models()[0], util.get_addr(program, 0x402000));
        assertEquals(diff.get_name().get_new_name(), "func_402000Dummy");
        for (DiffPair pair : diff.get_params()) {
            assertEquals(pair.get_new_name().substring(pair.get_new_name().length() - 5), "Dummy");
        }
        for (DiffPair pair : diff.get_vars()) {
            assertEquals(pair.get_new_name().substring(pair.get_new_name().length() - 5), "Dummy");
        }
    }


    @Test
    void test_guess_all() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Ai ai = new Ai(null, program, null);
        Guess guess = new Guess(gu, ai, new Model[] {new ModelDummy("Dummy1", "dummy.py"),
                new ModelDummy("Dummy2", "dummy.py")});
        DecomDiff[] diffs = guess.guess_all(util.get_addr(program, 0x402000));

        for (DecomDiff diff : diffs) {
            assertEquals(diff.get_name().get_new_name(), "func_402000" + diff.get_model().get_name());
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
        }
    }

    void test_guess_selected() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Ai ai = new Ai(null, program, null);
        Guess guess = new Guess(gu, ai, new Model[] {new ModelDummy("Dummy1", "dummy.py"),
                new ModelDummy("Dummy2", "dummy.py")});
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
    }
}
