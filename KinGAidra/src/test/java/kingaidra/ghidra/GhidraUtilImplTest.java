package kingaidra.ghidra;

import org.junit.jupiter.api.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.data.DataType;
import ghidra.util.task.TaskMonitor;
import kingaidra.decom.DecomDiff;
import kingaidra.testutil.GhidraTestUtil;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.AbstractMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

class GhidraUtilImplTest {

    @Test
    void test() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);

        // gu.get_current_addr();

        assertEquals(gu.get_func(util.get_addr(program, 0x401002)).getEntryPoint().getOffset(),
                0x401000);
        assertEquals(gu.get_func("func_401000").get(0).getEntryPoint().getOffset(),
                0x401000);

        assertTrue(
                gu.get_decom(util.get_addr(program, 0x401002)).contains("int func_401000(void)"));
        assertEquals(gu.get_asm(util.get_addr(program, 0x401002)),
                "func_401000:\n    PUSH EBP\n    MOV EBP,ESP\n    POP EBP\n    RET\n");

        List<Reference> refs = gu.get_ref_to(util.get_addr(program, 0x401000));
        assertEquals(refs.size(), 1);
        assertEquals(refs.get(0).getFromAddress(), util.get_addr(program, 0x403008));
        assertEquals(refs.get(0).getToAddress(), util.get_addr(program, 0x401000));
    }

    @Test
    void test_call_tree() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);

        List<Function> root = new LinkedList<>();
        gu.get_root_func(root);
        assertEquals(root.size(), 3);
        assertEquals(root.get(0).getEntryPoint().getOffset(), 0x404000);
        assertEquals(root.get(1).getEntryPoint().getOffset(), 0x406000);
        assertEquals(root.get(2).getEntryPoint().getOffset(), 0x408000);

        assertEquals(gu.get_func_call_tree(gu.get_func(util.get_addr(program, 0x403000))),
                                "- func_403000\n" +
                                "    - func_401000\n" +
                                "    - func_402000\n");
        assertEquals(gu.get_func_call_tree(), "- func_404000\n" +
                                "    - func_403000\n" +
                                "        - func_401000\n" +
                                "        - func_402000\n" +
                                "    - func_405000\n" +
                                "- func_406000\n" +
                                "    - func_405000\n" +
                                "        - func_402000\n" +
                                "- func_408000\n" +
                                "    - func_407000\n");

        assertEquals(gu.get_call_tree_parent("- func_404000\n" +
                                "    - func_403000\n" +
                                "        - func_401000\n" +
                                "        - func_402000\n" +
                                "    - func_405000\n" +
                                "- func_406000\n" +
                                "    - func_405000\n" +
                                "        - func_402000\n" +
                                "- func_408000\n" +
                                "    - func_407000\n", 1, gu.get_func(util.get_addr(program, 0x404000))).toString(), "[]");
        assertEquals(gu.get_call_tree_parent("- func_404000\n" +
                                "    - func_403000\n" +
                                "        - func_401000\n" +
                                "        - func_402000\n" +
                                "    - func_405000\n" +
                                "- func_406000\n" +
                                "    - func_405000\n" +
                                "        - func_402000\n" +
                                "- func_408000\n" +
                                "    - func_407000\n", 1, gu.get_func(util.get_addr(program, 0x403000))).toString(), "[func_404000]");
        assertEquals(gu.get_call_tree_parent("- func_404000\n" +
                                "    - func_403000\n" +
                                "        - func_401000\n" +
                                "        - func_402000\n" +
                                "    - func_405000\n" +
                                "- func_406000\n" +
                                "    - func_405000\n" +
                                "        - func_402000\n" +
                                "- func_408000\n" +
                                "    - func_407000\n", 1, gu.get_func(util.get_addr(program, 0x405000))).toString(), "[func_404000, func_406000]");
        assertEquals(gu.get_call_tree_parent("- func_404000\n" +
                                "    - func_403000\n" +
                                "        - func_401000\n" +
                                "        - func_402000\n" +
                                "    - func_405000\n" +
                                "- func_406000\n" +
                                "    - func_405000\n" +
                                "        - func_402000\n" +
                                "- func_408000\n" +
                                "    - func_407000\n", 1, gu.get_func(util.get_addr(program, 0x402000))).toString(), "[func_403000, func_405000]");
        assertEquals(gu.get_call_tree_parent("- func_404000\n" +
                                "    - func_403000\n" +
                                "        - func_401000\n" +
                                "        - func_402000\n" +
                                "    - func_405000\n" +
                                "- func_406000\n" +
                                "    - func_405000\n" +
                                "        - func_402000\n" +
                                "- func_408000\n" +
                                "    - func_407000\n", 2, gu.get_func(util.get_addr(program, 0x407000))).toString(), "[]");
        assertEquals(gu.get_call_tree_parent("- func_404000\n" +
                                "    - func_403000\n" +
                                "        - func_401000\n" +
                                "        - func_402000\n" +
                                "    - func_405000\n" +
                                "- func_406000\n" +
                                "    - func_405000\n" +
                                "        - func_402000\n" +
                                "- func_408000\n" +
                                "    - func_407000\n", 2, gu.get_func(util.get_addr(program, 0x402000))).toString(), "[func_404000, func_406000]");
        assertEquals(gu.get_call_tree_parent("- func_404000\n" +
                                "    - func_405000\n" +
                                "        - func_402000\n" +
                                "- func_406000\n" +
                                "    - func_405000\n" +
                                "        - func_402000\n" +
                                "- func_408000\n" +
                                "    - func_402000\n", 1, gu.get_func(util.get_addr(program, 0x402000))).toString(), "[func_405000, func_408000]");
    }

    @Test
    void test_strings() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);

        Data[] strs = gu.get_strings();
        assertEquals(strs.length, 5);
        assertEquals(strs[0].getAddress(), util.get_addr(program, 0x40f000));
        assertEquals((String) strs[0].getValue(), "string1");
        assertEquals(strs[1].getAddress(), util.get_addr(program, 0x40f100));
        assertEquals((String) strs[1].getValue(), "string2");
        assertEquals(strs[2].getAddress(), util.get_addr(program, 0x40f200));
        assertEquals((String) strs[2].getValue(), "string3");
        assertEquals(strs[3].getAddress(), util.get_addr(program, 0x40f300));
        assertEquals((String) strs[3].getValue(), "string4");
        assertEquals(strs[4].getAddress(), util.get_addr(program, 0x40f400));
        assertEquals((String) strs[4].getValue(), "string5");

        assertEquals(gu.get_strings_str(), "[40f000]=\"string1\"\n" +
                                "[40f100]=\"string2\"\n" +
                                "[40f200]=\"string3\"\n" +
                                "[40f300]=\"string4\"\n" +
                                "[40f400]=\"string5\"\n");
    }

    @Test
    void test_refactor() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        assertEquals(gu.get_decomdiff(util.get_addr(program, 0x402000)).get_name().get_var_name(),
                "func_402000");
        assertEquals(gu.get_decomdiff(util.get_addr(program, 0x402000)).get_name().get_new_name(),
                "func_402000");
        assertTrue(gu.get_decomdiff(util.get_addr(program, 0x402000)).get_src_code()
                .contains("int __fastcall func_402000(undefined *param_1)"));
        assertEquals(gu.get_decomdiff(util.get_addr(program, 0x402000)).get_params_len(), 1);
        assertEquals(gu.get_decomdiff(util.get_addr(program, 0x402000)).get_vars_len(), 7);
        assertEquals(gu.get_decomdiff(util.get_addr(program, 0x402000)).get_datatypes_len(), 8);

        DecomDiff diff = gu.get_decomdiff(util.get_addr(program, 0x402000));
        diff.set_name("new_func");
        diff.set_param_new_name("param_1", "new_param_1");
        diff.set_datatype_new_name("param_1", "int");
        gu.refact(diff);
        assertEquals(gu.get_func(util.get_addr(program, 0x402000)).getName(), "new_func");
        assertTrue(gu.get_decom(util.get_addr(program, 0x402000))
                .contains("int __fastcall new_func(int new_param_1)"));
    }

    @Test
    void test_add_comments() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        List<Map.Entry<String, String>> comments = new LinkedList<>();
        comments.add(new AbstractMap.SimpleEntry<>("piVar1 = (int *)(unaff_EBX + -0x3f7bfe3f);", "comment1"));
        comments.add(new AbstractMap.SimpleEntry<>("do {", "comment2"));
        comments.add(new AbstractMap.SimpleEntry<>("return ((uint)in_EAX & 0xffffff04) - (int)in_stack_00000004;", "comment3"));
        comments.add(new AbstractMap.SimpleEntry<>("return (int)in_EAX - (int)in_stack_00000004;", "comment4"));
        gu.add_comments(util.get_addr(program, 0x402000), comments);

        String decom_result = gu.get_decom(util.get_addr(program, 0x402000));
        assertTrue(decom_result.replace(" ", "").contains("/*comment1*/\r\npiVar1=(int*)(unaff_EBX+-0x3f7bfe3f);\r\n"));
        assertTrue(decom_result.replace(" ", "").contains("do{\r\n/*comment2*/\r\n"));
        assertTrue(decom_result.replace(" ", "").contains("/*comment3*/\r\nreturn((uint)in_EAX&0xffffff04)-(int)in_stack_00000004;\r\n"));
        assertTrue(decom_result.replace(" ", "").contains("/*comment4*/\r\nreturn(int)in_EAX-(int)in_stack_00000004;\r\n"));
    }

    @Test
    void test_find_datatype() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        List<DataType> dt_list1 = new LinkedList<>();
        gu.find_datatypes("int", dt_list1);
        assertEquals(dt_list1.size(), 1);

        List<DataType> dt_list2 = new LinkedList<>();
        gu.find_datatypes("dummy", dt_list2);
        assertEquals(dt_list2.size(), 0);
    }

    @Test
    void test_parse_datatypes() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        DataType dt = gu.parse_datatypes("struct person1 {\n" +
                                "    char *name;\n" +
                                "    int age;\n" +
                                "    char *job;\n" +
                                "};\n" +
                                "struct schedule {\n" +
                                "    int year;        \n" +
                                "    int month;       \n" +
                                "    int day;         \n" +
                                "    int hour;        \n" +
                                "    char title[100]; \n" +
                                "};");
        gu.add_datatype(dt);
        List<DataType> dt_list = new LinkedList<>();
        gu.find_datatypes("person1", dt_list);
        assertEquals(dt_list.size(), 0);
        dt_list.clear();
        gu.find_datatypes("schedule", dt_list);
        assertEquals(dt_list.size(), 1);

        dt = gu.parse_datatypes("typedef char TCHAR;\n" +
                                "#define MAX_PATH 260\n" +
                                "typedef unsigned long DWORD;\n" +
                                "typedef long LONG;\n" +
                                "typedef unsigned long ULONG_PTR;\n" +
                                "typedef struct tagPROCESSENTRY32 {\n" +
                                "    DWORD dwSize;               \n" +
                                "    DWORD cntUsage;             \n" +
                                "    DWORD th32ProcessID;        \n" +
                                "    ULONG_PTR th32DefaultHeapID;\n" +
                                "    DWORD th32ModuleID;         \n" +
                                "    DWORD cntThreads;           \n" +
                                "    DWORD th32ParentProcessID;  \n" +
                                "    LONG pcPriClassBase;        \n" +
                                "    DWORD dwFlags;              \n" +
                                "    TCHAR szExeFile[MAX_PATH];       \n" +
                                "} PROCESSENTRY32;");
        gu.add_datatype(dt);
        dt_list.clear();
        gu.find_datatypes("DWORD", dt_list);
        assertEquals(dt_list.size(), 1);
        dt_list.clear();
        gu.find_datatypes("ULONG_PTR", dt_list);
        assertEquals(dt_list.size(), 1);
        dt_list.clear();
        gu.find_datatypes("PROCESSENTRY32", dt_list);
        assertEquals(dt_list.size(), 1);

        dt = gu.parse_datatypes("typedef struct _RTL_DRIVE_LETTER_CURDIR {\n" +
                                "    unsigned short Length;\n" +
                                "    unsigned short Flags;\n" +
                                "    unsigned long  DriveLetter;\n" +
                                "    wchar_t        CurrentPath[1];   // this is a dynamic size array, typically varies\n" +
                                "} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;\n" +
                                "\n" +
                                "typedef struct _RTL_USER_PROCESS_PARAMETERS {\n" +
                                "    unsigned long MaximumLength;\n" +
                                "    unsigned long Length;\n" +
                                "    unsigned long Flags;\n" +
                                "    unsigned long DebugFlags;\n" +
                                "    void* ConsoleHandle;\n" +
                                "    unsigned long ConsoleFlags;\n" +
                                "    void* StandardInput;\n" +
                                "    void* StandardOutput;\n" +
                                "    void* StandardError;\n" +
                                "    PRTL_DRIVE_LETTER_CURDIR CurrentDirectory;\n" +
                                "    wchar_t* DllPath;\n" +
                                "    wchar_t* ImagePathName;\n" +
                                "    wchar_t* CommandLine;\n" +
                                "    wchar_t* Environment;\n" +
                                "    unsigned long StartingX;\n" +
                                "    unsigned long StartingY;\n" +
                                "    unsigned long CountX;\n" +
                                "    unsigned long CountY;\n" +
                                "    unsigned long CountCharsX;\n" +
                                "    unsigned long CountCharsY;\n" +
                                "    unsigned long ConsoleTextAttributes;\n" +
                                "    unsigned long ConsoleFullScreen;\n" +
                                "    unsigned long ConsoleKeyShortcuts;\n" +
                                "    wchar_t* DefaultTerminal;\n" +
                                "} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;\n" +
                                "\n" +
                                "typedef struct _PEB_LDR_DATA {\n" +
                                "    unsigned long Length;\n" +
                                "    unsigned long Initialized;\n" +
                                "    void* SsHandle;\n" +
                                "    void* InLoadOrderModuleList;\n" +
                                "    void* InMemoryOrderModuleList;\n" +
                                "    void* InInitializationOrderModuleList;\n" +
                                "} PEB_LDR_DATA, *PPEB_LDR_DATA;\n" +
                                "\n" +
                                "typedef struct _PEB {\n" +
                                "    unsigned char InheritedAddressSpace;\n" +
                                "    unsigned char ReadImageFileExecOptions;\n" +
                                "    unsigned char BeingDebugged;\n" +
                                "    unsigned char SpareBool;\n" +
                                "    void* Mutant;\n" +
                                "    void* ImageBaseAddress;\n" +
                                "    PEB_LDR_DATA* Ldr;\n" +
                                "    PRTL_USER_PROCESS_PARAMETERS* ProcessParameters;\n" +
                                "    void* SubSystemData;\n" +
                                "    void* ProcessHeap;\n" +
                                "    PRTL_USER_PROCESS_PARAMETERS* FastPebLock;\n" +
                                "    void* AtlThunkSListPtr;\n" +
                                "    void* IFEOKey;\n" +
                                "    PEB_LDR_DATA* CrossProcessFlags;\n" +
                                "    unsigned long KernelCallbackTable;\n" +
                                "    unsigned long UserSharedInfoPtr;\n" +
                                "    unsigned long SystemReserved;\n" +
                                "    unsigned long AtlThunkSListPtr32;\n" +
                                "    void* ApiSetMap;\n" +
                                "    unsigned long TlsExpansionCounter;\n" +
                                "    void* TlsBitmap;\n" +
                                "    unsigned long TlsBitmapBits[2];\n" +
                                "    void* ReadOnlySharedMemoryBase;\n" +
                                "    void* SharedData;\n" +
                                "    void* ReadOnlySharedMemoryHeap;\n" +
                                "    void* TlsExpansionBitmap;\n" +
                                "    unsigned long TlsExpansionBitmapBits[2];\n" +
                                "    unsigned long SessionId;\n" +
                                "} PEB, *PPEB;");// wrong
        gu.add_datatype(dt);
        dt_list.clear();
        // PEB
        gu.find_datatypes("PPEB", dt_list);
        assertEquals(dt_list.size(), 1);
        dt_list.clear();
        gu.find_datatypes("PEB_LDR_DATA", dt_list);
        assertEquals(dt_list.size(), 1);

        dt_list.clear();
        gu.find_datatypes("dummy", dt_list);
        assertEquals(dt_list.size(), 0);
    }
}
