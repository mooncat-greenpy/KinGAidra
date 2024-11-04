package kingaidra.ghidra;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
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

        assertTrue(gu.get_decom(util.get_addr(program, 0x401002)).contains("void func(void)"));
    }
}
