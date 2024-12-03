package kingaidra.chat.ai;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.ai.TaskType;
import kingaidra.chat.Conversation;
import kingaidra.chat.ConversationContainer;
import kingaidra.chat.KinGAidraChatTaskService;

public class Ai {
    private PluginTool tool;
    private Program program;
    private ConversationContainer container;
    private KinGAidraChatTaskService service;

    public Ai(PluginTool tool, Program program, ConversationContainer container, KinGAidraChatTaskService service) {
        this.tool = tool;
        this.program = program;
        this.container = container;
        this.service = service;
    }

    public Conversation guess(Conversation convo) {
        Conversation rep = convo.get_model().guess(TaskType.CHAT, convo, service, tool, program);
        if (rep != null) {
            container.add_convo(rep);
        }
        return rep;
    }
}
