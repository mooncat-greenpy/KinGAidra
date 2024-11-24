package kingaidra.ghidra;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidra.program.model.data.DataType;
import ghidra.util.task.TaskMonitor;
import kingaidra.decom.DecomDiff;
import kingaidra.testutil.GhidraTestUtil;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedList;
import java.util.List;

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
                gu.get_decom(util.get_addr(program, 0x401002)).contains("int func_401000(void)"));
        assertEquals(gu.get_asm(util.get_addr(program, 0x401002)),
                "func_401000:\n    PUSH EBP\n    MOV EBP,ESP\n    POP EBP\n    RET\n");
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

        dt = gu.parse_datatypes("typedef unsigned long DWORD;\n" +
                                "\n" +
                                "typedef long LONG;\n" +
                                "\n" +
                                "typedef void* PVOID;\n" +
                                "\n" +
                                "typedef char TCHAR;\n" +
                                "\n" +
                                "#define MAX_PATH 260" +
                                "\n" +
                                "typedef struct _LIST_ENTRY {\n" +
                                "    struct _LIST_ENTRY* Flink;\n" +
                                "    struct _LIST_ENTRY* Blink;\n" +
                                "} LIST_ENTRY;\n" +
                                "\n" +
                                "typedef struct _PEB_LDR_DATA {\n" +
                                "    DWORD Length;\n" +
                                "    DWORD Initialized;\n" +
                                "    PVOID SsHandle;\n" +
                                "    LIST_ENTRY InLoadOrderModuleList;\n" +
                                "    LIST_ENTRY InMemoryOrderModuleList;\n" +
                                "    LIST_ENTRY InInitializationOrderModuleList;\n" +
                                "} PEB_LDR_DATA;\n" +
                                "\n" +
                                "typedef struct _RTL_USER_PROCESS_PARAMETERS {\n" +
                                "    DWORD MaximumLength;\n" +
                                "    DWORD Length;\n" +
                                "    DWORD Flags;\n" +
                                "    DWORD DebugFlags;\n" +
                                "    PVOID ConsoleHandle;\n" +
                                "    DWORD ConsoleFlags;\n" +
                                "    PVOID StandardInput;\n" +
                                "    PVOID StandardOutput;\n" +
                                "    PVOID StandardError;\n" +
                                "    LIST_ENTRY CurrentDirectoryPath;\n" +
                                "    PVOID CurrentDirectoryHandle;\n" +
                                "    TCHAR DllPath[MAX_PATH];\n" +
                                "    TCHAR ImagePathName[MAX_PATH];\n" +
                                "    TCHAR CommandLine[MAX_PATH];\n" +
                                "    PVOID Environment;\n" +
                                "    DWORD StartingPositionLeft;\n" +
                                "    DWORD StartingPositionTop;\n" +
                                "    DWORD Width;\n" +
                                "    DWORD Height;\n" +
                                "    DWORD CharWidth;\n" +
                                "    DWORD CharHeight;\n" +
                                "    DWORD ConsoleTextAttribute;\n" +
                                "    DWORD ConsoleWindowFlags;\n" +
                                "    DWORD ConsoleScreenBufferSize;\n" +
                                "    DWORD ConSelection;\n" +
                                "    PVOID hConsoleOutput;\n" +
                                "    PVOID hConsoleInput;\n" +
                                "    PVOID hConsoleError;\n" +
                                "} RTL_USER_PROCESS_PARAMETERS;\n" +
                                "\n" +
                                "typedef struct _PEB {\n" +
                                "    DWORD Reserved1[2];\n" +
                                "    PVOID BeingDebugged;\n" +
                                "    PVOID Reserved2[1];\n" +
                                "    PEB_LDR_DATA* Ldr;\n" +
                                "    RTL_USER_PROCESS_PARAMETERS* ProcessParameters;\n" +
                                "    PVOID Reserved3[3];\n" +
                                "    DWORD AtlThunkSListPtr;\n" +
                                "    PVOID Reserved4;\n" +
                                "    DWORD Reserved5;\n" +
                                "    DWORD CriticalSectionTimeout;\n" +
                                "    PVOID HeapSegmentReserve;\n" +
                                "    PVOID HeapSegmentCommit;\n" +
                                "    PVOID HeapDeCommitTotalFreeThreshold;\n" +
                                "    PVOID HeapDeCommitFreeBlockThreshold;\n" +
                                "    DWORD NumberOfHeaps;\n" +
                                "    DWORD MaximumNumberOfHeaps;\n" +
                                "    PVOID ProcessHeaps;\n" +
                                "    PVOID GdiSharedHandleTable;\n" +
                                "    PVOID ProcessStarterHelper;\n" +
                                "    DWORD GdiDCAttributeList;\n" +
                                "    PVOID LoaderLock;\n" +
                                "    DWORD OSMajorVersion;\n" +
                                "    DWORD OSMinorVersion;\n" +
                                "    DWORD OSBuildNumber;\n" +
                                "    DWORD OSPlatformId;\n" +
                                "    DWORD ImageSubsystem;\n" +
                                "    DWORD ImageSubsystemMajorVersion;\n" +
                                "    DWORD ImageSubsystemMinorVersion;\n" +
                                "    PVOID ImageEntryPoint;\n" +
                                "    PVOID ImageBaseAddress;\n" +
                                "    DWORD LoadOrder;\n" +
                                "    DWORD StackBase;\n" +
                                "    DWORD StackLimit;\n" +
                                "    DWORD CurrentDirectory;\n" +
                                "    PVOID KernelBaseAddress;\n" +
                                "    PVOID UserBaseAddress;\n" +
                                "    DWORD UserProfilePath;\n" +
                                "    DWORD GdiSharedHandleTableIndex;\n" +
                                "    DWORD NumberOfGdiSharedHandles;\n" +
                                "    DWORD GdiSharedHandleTableHandle;\n" +
                                "} PEB;");
        gu.add_datatype(dt);
        dt_list.clear();
        gu.find_datatypes("PEB", dt_list);
        assertEquals(dt_list.size(), 1);
        dt_list.clear();
        gu.find_datatypes("PEB_LDR_DATA", dt_list);
        assertEquals(dt_list.size(), 1);

        dt_list.clear();
        gu.find_datatypes("dummy", dt_list);
        assertEquals(dt_list.size(), 0);
    }
}
