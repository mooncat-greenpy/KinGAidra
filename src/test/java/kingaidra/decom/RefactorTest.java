package kingaidra.decom;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.testutil.GhidraTestUtil;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RefactorTest {
    @Test
    void test_refact() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        Refactor refactor = new Refactor(gu);

        assertEquals(gu.get_func(util.get_addr(program, 0x402000)).getName(), "func_402000");
        assertTrue(gu.get_decomdiff(util.get_addr(program, 0x402000)).get_src_code()
                .contains("int __fastcall func_402000(undefined *param_1)"));

        DecomDiff diff = gu.get_decomdiff(util.get_addr(program, 0x402000));
        diff.set_name("new_func");
        diff.set_param_new_name("param_1", "new_param_1");
        for (DiffPair pair : diff.get_vars()) {
            pair.set_new_name(pair.get_old_name() + "_new");
        }

        refactor.refact(diff);
        assertEquals(gu.get_func(util.get_addr(program, 0x402000)).getName(), "new_func");
        assertTrue(gu.get_decom(util.get_addr(program, 0x402005))
                .contains("int __fastcall new_func(undefined *new_param_1)"));
        for (DiffPair pair : gu.get_decomdiff(util.get_addr(program, 0x402000)).get_vars()) {
            assertEquals(pair.get_new_name().substring(pair.get_new_name().length() - 4), "_new");
        }
    }
}
