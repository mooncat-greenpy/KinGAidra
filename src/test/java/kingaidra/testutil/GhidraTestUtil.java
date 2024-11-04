package kingaidra.testutil;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class GhidraTestUtil {
    static boolean is_init = false;

    public GhidraTestUtil() throws Exception {
        init();
    }

    static void init() throws Exception {
        if (is_init) {
            return;
        }
        GhidraApplicationLayout layout = new GhidraApplicationLayout();
        HeadlessGhidraApplicationConfiguration configuration =
                new HeadlessGhidraApplicationConfiguration();
        Application.initializeApplication(layout, configuration);
        is_init = true;
    }

    public Program create_program() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("test", ProgramBuilder._X86, null);
        builder.createMemory(".text", "0x0401000", 0x9000);
        builder.setBytes("0x401000", "55 89 e5 5d c3");
        builder.createEmptyFunction("func", "0x401000", 0x5, null);

        builder.analyze();
        return builder.getProgram();
    }

    public Address get_addr(Program program, long addr) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
    }
}
