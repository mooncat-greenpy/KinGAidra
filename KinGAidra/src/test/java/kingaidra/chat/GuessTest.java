package kingaidra.chat;

import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerDummy;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelConfSingle;
import kingaidra.ai.task.TaskType;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.ghidra.PromptConf;
import kingaidra.testutil.GhidraTestUtil;
import kingaidra.testutil.ModelDummy;
import kingaidra.testutil.ChatModelDummy;
import kingaidra.testutil.ChatModelPreferencesDummy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

public class GuessTest {
    @Test
    void test_constructor() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ChatModelDummy("Dummy", "dummy.py", true));
        ModelConfSingle model_conf = new ModelConfSingle("chat", pref);
        Guess guess = new Guess(ai, model_conf, conf);
        assertTrue(model_conf.exist_model("Dummy"));
        assertFalse(model_conf.exist_model("Dummy1"));
        assertEquals(model_conf.get_model_script("Dummy"), "dummy.py");
        assertEquals(model_conf.get_models_len(), 1);
        assertEquals(model_conf.get_models()[0], "Dummy");
        assertEquals(model_conf.get_model_status(model_conf.get_models()[0]), true);
        // Not suppoort
        // assertEquals(model_conf.get_model_status(new ChatModelDummy("Dummy", "dummy.py", true)),
        // false);
    }

    @Test
    void test_set_model_name_script() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy", new ChatModelDummy("Dummy", "dummy.py", true));
        ModelConfSingle model_conf = new ModelConfSingle("chat", pref);
        Guess guess = new Guess(ai, model_conf, conf);
        model_conf.set_model_name("Dummy", "d");
        model_conf.set_model_script("d", "d.py");
        assertTrue(model_conf.exist_model("d"));
        assertFalse(model_conf.exist_model("Dummy"));
        assertEquals(model_conf.get_model_script("d"), "d.py");
    }

    @Test
    void test_set_model_status() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref1 = new ChatModelPreferencesDummy();
        pref1.store("Dummy1", new ChatModelDummy("Dummy1", "dummy.py", true));
        pref1.store("Dummy2", new ChatModelDummy("Dummy2", "dummy.py", true));
        pref1.store("Dummy3", new ChatModelDummy("Dummy3", "dummy.py", true));
        ModelConfSingle model_conf1 = new ModelConfSingle("chat", pref1);
        Guess guess1 = new Guess(ai, model_conf1, conf);
        assertEquals(model_conf1.get_model_status("Dummy1"), true);
        assertEquals(model_conf1.get_model_status("Dummy2"), false);
        assertEquals(model_conf1.get_model_status("Dummy3"), false);
        model_conf1.set_model_status("Dummy1", true);
        assertEquals(model_conf1.get_model_status("Dummy1"), true);
        assertEquals(model_conf1.get_model_status("Dummy2"), false);
        assertEquals(model_conf1.get_model_status("Dummy3"), false);
        model_conf1.set_model_status("Dummy1", false);
        assertEquals(model_conf1.get_model_status("Dummy1"), true);
        assertEquals(model_conf1.get_model_status("Dummy2"), false);
        assertEquals(model_conf1.get_model_status("Dummy3"), false);

        GhidraPreferences<Model> pref2 = new ChatModelPreferencesDummy();
        pref2.store("Dummy1", new ChatModelDummy("Dummy1", "dummy.py", false));
        pref2.store("Dummy2", new ChatModelDummy("Dummy2", "dummy.py", false));
        pref2.store("Dummy3", new ChatModelDummy("Dummy3", "dummy.py", false));
        ModelConfSingle model_conf2 = new ModelConfSingle("chat", pref2);
        Guess guess2 = new Guess(ai, model_conf2, conf);
        assertEquals(model_conf2.get_model_status("Dummy1"), true);
        assertEquals(model_conf2.get_model_status("Dummy2"), false);
        assertEquals(model_conf2.get_model_status("Dummy3"), false);
    }

    @Test
    void test_guess() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy1", new ChatModelDummy("Dummy1", "dummy.py", false));
        pref.store("Dummy2", new ChatModelDummy("Dummy2", "dummy.py", true));
        pref.store("Dummy3", new ChatModelDummy("Dummy3", "dummy.py", false));
        ModelConfSingle model_conf = new ModelConfSingle("chat", pref);
        Guess guess = new Guess(ai, model_conf, conf);
        Conversation convo1 = guess.guess(TaskType.CHAT, "msg", util.get_addr(program, 0x402000));
        assertEquals(convo1.get_type(), ConversationType.USER_CHAT);
        assertEquals(convo1.get_msgs_len(), 2);
        assertEquals(convo1.get_msg(0), "msg");
        assertEquals(convo1.get_msg(1), "msgDummy2");
        assertEquals(convo1.get_addrs().length, 0);
        guess.guess(TaskType.CHAT, convo1, "Explain\n<code>", util.get_addr(program, 0x402000));
        assertEquals(convo1.get_type(), ConversationType.USER_CHAT);
        assertEquals(convo1.get_msgs_len(), 4);
        assertEquals(convo1.get_msg(0), "msg");
        assertEquals(convo1.get_msg(1), "msgDummy2");
        assertTrue(convo1.get_msg(2).contains("int __fastcall func_402000(undefined *param_1)"));
        assertTrue(convo1.get_msg(3).endsWith("Dummy2"));
        assertEquals(convo1.get_addrs().length, 1);
        assertEquals(convo1.get_addrs()[0].getOffset(), 0x402000);

        Conversation convo2 = guess.guess(TaskType.CHAT, "msg", util.get_addr(program, 0x401000));
        guess.guess(TaskType.CHAT, convo2, "Explain\n<asm>", util.get_addr(program, 0x401000));
        assertEquals(convo2.get_type(), ConversationType.USER_CHAT);
        assertEquals(convo2.get_msgs_len(), 4);
        assertEquals(convo2.get_msg(0), "msg");
        assertEquals(convo2.get_msg(1), "msgDummy2");
        assertTrue(convo2.get_msg(2)
                .contains("func_401000:\n    PUSH EBP\n    MOV EBP,ESP\n    POP EBP\n    RET\n"));
        assertTrue(convo2.get_msg(3).endsWith("Dummy2"));
        assertEquals(convo2.get_addrs().length, 1);
        assertEquals(convo2.get_addrs()[0].getOffset(), 0x401000);

        Conversation convo3 = guess.guess(TaskType.CHAT, "msg", util.get_addr(program, 0x408000));
        guess.guess(TaskType.CHAT, convo3, "Explain\n<calltree>", util.get_addr(program, 0x408000));
        assertEquals(convo3.get_type(), ConversationType.USER_CHAT);
        assertEquals(convo3.get_msgs_len(), 4);
        assertEquals(convo3.get_msg(0), "msg");
        assertEquals(convo3.get_msg(1), "msgDummy2");
        assertTrue(convo3.get_msg(2).contains("- func_408000\n" +
                                "    - func_407000\n"));
        assertTrue(convo3.get_msg(3).endsWith("Dummy2"));
        assertEquals(convo3.get_addrs().length, 1);
        assertEquals(convo3.get_addrs()[0].getOffset(), 0x408000);
    }

    @Test
    void test_guess_src_code_comments() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtil gu = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(null, program, gu, container, null, conf);
        GhidraPreferences<Model> pref = new ChatModelPreferencesDummy();
        pref.store("Dummy1", new ModelDummy("Dummy1", "dummy.py", false));
        pref.store("Dummy2", new ModelDummy("Dummy2", "dummy.py", true));
        pref.store("Dummy3", new ModelDummy("Dummy3", "dummy.py", false));
        ModelConfSingle model_conf = new ModelConfSingle("chat", pref);
        Guess guess = new Guess(ai, model_conf, conf);
        List<Map.Entry<String, String>> comments = guess.guess_src_code_comments(util.get_addr(program, 0x402000));
        assertEquals(comments.size(), 4);
        assertEquals(comments.get(0).getKey(), "piVar1 = (int *)(unaff_EBX + -0x3f7bfe3f);");
        assertEquals(comments.get(0).getValue(), "comment1");
        assertEquals(comments.get(1).getKey(), "do {");
        assertEquals(comments.get(1).getValue(), "comment2");
        assertEquals(comments.get(2).getKey(), "return ((uint)in_EAX & 0xffffff04) - (int)in_stack_00000004;");
        assertEquals(comments.get(2).getValue(), "comment3");
        assertEquals(comments.get(3).getKey(), "return (int)in_EAX - (int)in_stack_00000004;");
        assertEquals(comments.get(3).getValue(), "comment4");
    }
}
