package kingaidra.chat.ai;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.chat.Conversation;
import kingaidra.chat.KinGAidraChatTaskService;

public class Ai {
    private PluginTool tool;
    private Program program;
    private KinGAidraChatTaskService service;

    public Ai(PluginTool tool, Program program, KinGAidraChatTaskService service) {
        this.tool = tool;
        this.program = program;
        this.service = service;
    }

    public Conversation guess(Conversation convo) {
        return convo.get_model().guess(convo, service, tool, program);
    }
}
