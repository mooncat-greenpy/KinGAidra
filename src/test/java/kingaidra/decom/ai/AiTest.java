package kingaidra.decom.ai;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.DiffPair;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.testutil.GhidraTestUtil;
import kingaidra.testutil.ModelDummy;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class AiTest {


    @Test
    void test_constructor() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        Ai ai = new Ai(null, program, new Model[] {new ModelDummy("Dummy1", "dummy1.py"),
                new ModelDummy("Dummy2", "dummy2.py")}, null);
        assertEquals(ai.get_support_model()[0].get_name(), "Dummy1");
        assertEquals(ai.get_support_model()[1].get_name(), "Dummy2");

    }

    @Test
    void test_guess() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        Ai ai = new Ai(null, program, new Model[] {new ModelDummy("Dummy", "dummy.py")}, null);

        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        DecomDiff diff = gu.get_decomdiff(util.get_addr(program, 0x401000));
        diff.set_model(ai.get_support_model()[0]);

        diff = ai.guess(diff);
        assertEquals(diff.get_name().get_new_name(), "func" + "Dummy");
        for (DiffPair pair : diff.get_params()) {
            assertEquals(
                    pair.get_new_name().substring(
                            pair.get_new_name().length() - diff.get_model().get_name().length()),
                    "Dummy");
        }
        for (DiffPair pair : diff.get_vars()) {
            assertEquals(
                    pair.get_new_name().substring(
                            pair.get_new_name().length() - diff.get_model().get_name().length()),
                    "Dummy");
        }
    }
}
