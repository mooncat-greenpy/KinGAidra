package kingaidra.ai;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerDummy;
import kingaidra.ai.task.TaskType;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.testutil.GhidraTestUtil;
import kingaidra.testutil.ChatModelDummy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AiTest {

    @Test
    void test_resolve_src_code() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(null, program, gu, container, null);
        Conversation convo1 = new Conversation(new ChatModelDummy("Dummy", "dummy.py", true));
        String ret1 = ai.resolve_src_code(convo1, "Explain\n<code:401000>\nend",
                util.get_addr(program, 0x402000));
        assertFalse(ret1.contains("int __fastcall func_402000(undefined *param_1)"));
        assertTrue(ret1.startsWith("Explain\n"));
        assertTrue(ret1.contains("int func_401000(void)"));
        assertTrue(ret1.endsWith("\nend"));
        assertEquals(convo1.get_addrs().length, 1);
        assertEquals(convo1.get_addrs()[0].getOffset(), 0x401000);

        Conversation convo2 = new Conversation(new ChatModelDummy("Dummy", "dummy.py", true));
        String ret2 =
                ai.resolve_src_code(convo2, "Explain\n<code:401000>\nand\n<code:402000>\nend",
                        util.get_addr(program, 0x402000));
        assertTrue(ret2.startsWith("Explain\n"));
        assertTrue(ret2.contains("int __fastcall func_402000(undefined *param_1)"));
        assertTrue(ret2.contains("\nand\n"));
        assertTrue(ret2.contains("int func_401000(void)"));
        assertTrue(ret2.endsWith("\nend"));
        assertEquals(convo2.get_addrs().length, 2);
        assertEquals(convo2.get_addrs()[0].getOffset(), 0x401000);
        assertEquals(convo2.get_addrs()[1].getOffset(), 0x402000);

        Conversation convo3 = new Conversation(new ChatModelDummy("Dummy", "dummy.py", true));
        String ret3 = ai.resolve_src_code(convo3, "Explain\n<code:401000>\nand\n<code>\nend",
                util.get_addr(program, 0x402000));
        assertTrue(ret3.startsWith("Explain\n"));
        assertTrue(ret3.contains("int __fastcall func_402000(undefined *param_1)"));
        assertTrue(ret3.contains("\nand\n"));
        assertTrue(ret3.contains("int func_401000(void)"));
        assertTrue(ret3.endsWith("\nend"));
        assertEquals(convo3.get_addrs().length, 2);
        assertEquals(convo3.get_addrs()[0].getOffset(), 0x402000);
        assertEquals(convo3.get_addrs()[1].getOffset(), 0x401000);
    }

    @Test
    void test_resolve_asm_code() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(null, program, gu, container, null);
        Conversation convo1 = new Conversation(new ChatModelDummy("Dummy", "dummy.py", true));
        String ret1 = ai.resolve_asm_code(convo1, "Explain\n<asm:401000>\nend",
                util.get_addr(program, 0x402000));
        assertFalse(ret1.contains("MOV ECX,dword ptr [ESP + 0x4]"));
        assertTrue(ret1.startsWith("Explain\n"));
        assertTrue(ret1
                .contains("func_401000:\n    PUSH EBP\n    MOV EBP,ESP\n    POP EBP\n    RET\n"));
        assertTrue(ret1.endsWith("\nend"));
        assertEquals(convo1.get_addrs().length, 1);
        assertEquals(convo1.get_addrs()[0].getOffset(), 0x401000);

        Conversation convo2 = new Conversation(new ChatModelDummy("Dummy", "dummy.py", true));
        String ret2 = ai.resolve_asm_code(convo2,
                "Explain\n<asm:401000>\nand\n<asm:402000>\nend", util.get_addr(program, 0x402000));
        assertTrue(ret2.startsWith("Explain\n"));
        assertTrue(ret2
                .contains("func_401000:\n    PUSH EBP\n    MOV EBP,ESP\n    POP EBP\n    RET\n"));
        assertTrue(ret2.contains("\nand\n"));
        assertTrue(ret2.contains("MOV ECX,dword ptr [ESP + 0x4]"));
        assertTrue(ret2.endsWith("\nend"));
        assertEquals(convo2.get_addrs().length, 2);
        assertEquals(convo2.get_addrs()[0].getOffset(), 0x401000);
        assertEquals(convo2.get_addrs()[1].getOffset(), 0x402000);

        Conversation convo3 = new Conversation(new ChatModelDummy("Dummy", "dummy.py", true));
        String ret3 = ai.resolve_asm_code(convo3, "Explain\n<asm:401000>\nand\n<asm>\nend",
                util.get_addr(program, 0x402000));
        assertTrue(ret3.startsWith("Explain\n"));
        assertTrue(ret3
                .contains("func_401000:\n    PUSH EBP\n    MOV EBP,ESP\n    POP EBP\n    RET\n"));
        assertTrue(ret3.contains("\nand\n"));
        assertTrue(ret3.contains("MOV ECX,dword ptr [ESP + 0x4]"));
        assertTrue(ret3.endsWith("\nend"));
        assertEquals(convo3.get_addrs().length, 2);
        assertEquals(convo3.get_addrs()[0].getOffset(), 0x402000);
        assertEquals(convo3.get_addrs()[1].getOffset(), 0x401000);
    }

    @Test
    void test_guess() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(null, program, gu, container, null);
        Conversation convo1 = new Conversation(new ChatModelDummy("Dummy1", "dummy.py", true));
        convo1 = ai.guess(TaskType.CHAT, convo1, "msg", util.get_addr(program, 0x402000));
        assertEquals(convo1.get_msgs_len(), 2);
        assertEquals(convo1.get_msg(0), "msg");
        assertEquals(convo1.get_msg(1), "msgDummy1");
        assertEquals(convo1.get_addrs().length, 0);
        ai.guess(TaskType.CHAT, convo1, "Explain\n<code>", util.get_addr(program, 0x402000));
        assertEquals(convo1.get_msgs_len(), 4);
        assertEquals(convo1.get_msg(0), "msg");
        assertEquals(convo1.get_msg(1), "msgDummy1");
        assertTrue(convo1.get_msg(2).contains("int __fastcall func_402000(undefined *param_1)"));
        assertTrue(convo1.get_msg(3).endsWith("Dummy1"));
        assertEquals(convo1.get_addrs().length, 1);
        assertEquals(convo1.get_addrs()[0].getOffset(), 0x402000);

        Conversation convo2 = new Conversation(new ChatModelDummy("Dummy1", "dummy.py", true));
        convo2 = ai.guess(TaskType.CHAT, convo2, "msg", util.get_addr(program, 0x401000));
        ai.guess(TaskType.CHAT, convo2, "Explain\n<asm>", util.get_addr(program, 0x401000));
        assertEquals(convo2.get_msgs_len(), 4);
        assertEquals(convo2.get_msg(0), "msg");
        assertEquals(convo2.get_msg(1), "msgDummy1");
        assertTrue(convo2.get_msg(2)
                .contains("func_401000:\n    PUSH EBP\n    MOV EBP,ESP\n    POP EBP\n    RET\n"));
        assertTrue(convo2.get_msg(3).endsWith("Dummy1"));
        assertEquals(convo2.get_addrs().length, 1);
        assertEquals(convo2.get_addrs()[0].getOffset(), 0x401000);
    }
}