package kingaidra.testutil;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

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
        builder.createEmptyFunction("func_401000", "0x401000", 0x5, null);

        Program program = builder.getProgram();
        builder.setBytes("0x402000",
                "8b 4c 24 04 f7 c1 03 74 24 8a 01 83 c1 01 84 c0 74 4e f7 c1 03 75 ef 05 00 00 8d a4 24 8d a4 24 8b 01 ba ff fe 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 74 e8 8b 41 fc 84 c0 74 32 84 e4 74 24 a9 00 00 74 13 a9 00 00 74 02 eb cd 8d 41 ff 8b 4c 24 04 2b c1 c3 8d 41 fe 8b 4c 24 04 2b c1 c3 8d 41 fd 8b 4c 24 04 2b c1 c3 8d 41 fc 8b 4c 24 04 2b c1 c3");
        DataType str_dt = new PointerDataType();
        Varnode vn1 = new Varnode(program.getAddressFactory().getStackSpace().getAddress(4), 4);
        VariableStorage v1 = new VariableStorage(program, new Varnode[] {vn1});
        Parameter p1 = new ParameterImpl("param_1", str_dt, v1, builder.getProgram(),
                SourceType.USER_DEFINED);
        builder.createEmptyFunction("func_402000", "0x402000", 0x72, new Undefined4DataType(), p1);
        builder.analyze();
        return builder.getProgram();
    }

    public Address get_addr(Program program, long addr) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
    }
}
