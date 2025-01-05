package kingaidra.testutil;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
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
        builder.createMemory(".text", "0x0401000", 0xf000);
        builder.setBytes("0x401000", "55 89 e5 5d c3");
        builder.createEmptyFunction("func_401000", "0x401000", 0x5, new IntegerDataType());

        Program program = builder.getProgram();
        builder.setBytes("0x402000",
                "8b 4c 24 04 f7 c1 03 74 24 8a 01 83 c1 01 84 c0 74 4e f7 c1 03 75 ef 05 00 00 8d a4 24 8d a4 24 8b 01 ba ff fe 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 74 e8 8b 41 fc 84 c0 74 32 84 e4 74 24 a9 00 00 74 13 a9 00 00 74 02 eb cd 8d 41 ff 8b 4c 24 04 2b c1 c3 8d 41 fe 8b 4c 24 04 2b c1 c3 8d 41 fd 8b 4c 24 04 2b c1 c3 8d 41 fc 8b 4c 24 04 2b c1 c3");
        DataType str_dt = new PointerDataType();
        Varnode vn1 = new Varnode(program.getAddressFactory().getStackSpace().getAddress(4), 4);
        VariableStorage v1 = new VariableStorage(program, new Varnode[] {vn1});
        Parameter p1 = new ParameterImpl("param_1", str_dt, v1, builder.getProgram(),
                SourceType.USER_DEFINED);
        builder.createEmptyFunction("func_402000", "0x402000", 0x72, new Undefined4DataType(), p1);

        // call func_402000, func_401000
        builder.setBytes("0x403000", "55 89 e5 e8 f8 ef ff ff e8 f3 df ff ff 5d c3");
        builder.createEmptyFunction("func_403000", "0x403000", 0xf, new IntegerDataType());

        // call func_403000, func_405000
        builder.setBytes("0x404000", "55 89 e5 e8 f8 ef ff ff e8 f3 0f 00 00 5d c3");
        builder.createEmptyFunction("func_404000", "0x404000", 0xf, new IntegerDataType());

        // call func_402000
        builder.setBytes("0x405000", "55 89 e5 e8 f8 cf ff ff 5d c3");
        builder.createEmptyFunction("func_405000", "0x405000", 0x5, new IntegerDataType());

        // call func_405000
        builder.setBytes("0x406000", "55 89 e5 e8 f8 ef ff ff 5d c3");
        builder.createEmptyFunction("func_406000", "0x406000", 0xf, new IntegerDataType());

        builder.setBytes("0x407000", "55 89 e5 5d c3");
        builder.createEmptyFunction("func_407000", "0x407000", 0x5, new IntegerDataType());

        // call func_407000
        builder.setBytes("0x408000", "55 89 e5 e8 f8 ef ff ff 5d c3");
        builder.createEmptyFunction("func_408000", "0x408000", 0xf, new IntegerDataType());

        // call func_40a000
        builder.setBytes("0x409000", "55 89 e5 e8 f8 0f 00 00 5d c3");
        builder.createEmptyFunction("func_409000", "0x409000", 0xf, new IntegerDataType());

        // call func_409000
        builder.setBytes("0x40a000", "55 89 e5 e8 f8 ef ff ff 5d c3");
        builder.createEmptyFunction("func_40a000", "0x40a000", 0xf, new IntegerDataType());

        builder.setBytes("0x40f000", "73 74 72 69 6e 67 31 00");
        builder.applyDataType("0x40f000", new StringDataType());
        builder.setBytes("0x40f100", "73 74 72 69 6e 67 32 00");
        builder.applyDataType("0x40f100", new TerminatedStringDataType());
        builder.setBytes("0x40f200", "73 74 72 69 6e 67 33 33");
        builder.applyDataType("0x40f200", new ArrayDataType(new CharDataType(), 7, 1));
        builder.setBytes("0x40f300", "73 74 72 69 6e 67 34 00");
        builder.applyDataType("0x40f300", new StringDataType());
        builder.setBytes("0x40f400", "73 74 72 69 6e 67 35 00");
        builder.applyDataType("0x40f400", new StringDataType());

        builder.analyze();
        return builder.getProgram();
    }

    public Address get_addr(Program program, long addr) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
    }
}
