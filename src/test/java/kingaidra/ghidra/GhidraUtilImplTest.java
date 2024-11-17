package kingaidra.ghidra;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.decom.DecomDiff;
import kingaidra.testutil.GhidraTestUtil;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GhidraUtilImplTest {

    @Test
    void test() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);

        // gu.get_current_addr();

        assertEquals(gu.get_func(util.get_addr(program, 0x401002)).getEntryPoint().getOffset(),
                0x401000);

        assertTrue(
                gu.get_decom(util.get_addr(program, 0x401002)).contains("void func_401000(void)"));
        assertEquals(gu.get_asm(util.get_addr(program, 0x401002)),
                "PUSH EBP\nMOV EBP,ESP\nPOP EBP\nRET\n");
    }

    @Test
    void test_refactor() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        assertEquals(gu.get_decomdiff(util.get_addr(program, 0x402000)).get_name().get_old_name(),
                "func_402000");
        assertEquals(gu.get_decomdiff(util.get_addr(program, 0x402000)).get_name().get_new_name(),
                "func_402000");
        assertTrue(gu.get_decomdiff(util.get_addr(program, 0x402000)).get_src_code()
                .contains("int __fastcall func_402000(undefined *param_1)"));
        assertEquals(gu.get_decomdiff(util.get_addr(program, 0x402000)).get_params_len(), 1);
        assertEquals(gu.get_decomdiff(util.get_addr(program, 0x402000)).get_vars_len(), 7);

        DecomDiff diff = gu.get_decomdiff(util.get_addr(program, 0x402000));
        diff.set_name("new_func");
        diff.set_param_new_name("param_1", "new_param_1");
        gu.refact(diff);
        assertEquals(gu.get_func(util.get_addr(program, 0x402000)).getName(), "new_func");
        assertTrue(gu.get_decom(util.get_addr(program, 0x402000))
                .contains("int __fastcall new_func(undefined *new_param_1)"));
    }
}
