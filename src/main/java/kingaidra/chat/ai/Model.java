package kingaidra.chat.ai;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.chat.Conversation;
import kingaidra.decom.ai.ModelType;
import kingaidra.decom.ai.TaskType;
import kingaidra.chat.KinGAidraChatTaskService;

public interface Model {
    public String get_name();

    public void set_name(String name);

    public String get_script();

    public void set_script(String script_file);

    public boolean get_active();

    public void set_active(boolean b);

    public ModelType get_type();

    public void set_type(ModelType type);

    public Conversation guess(TaskType type, Conversation convo, KinGAidraChatTaskService service, PluginTool tool,
            Program program);
}
