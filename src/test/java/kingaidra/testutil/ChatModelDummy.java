package kingaidra.testutil;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.chat.Conversation;
import kingaidra.decom.KinGAidraDecomTaskService;
import kingaidra.chat.ai.Model;
import kingaidra.decom.ai.ModelType;

public class ChatModelDummy implements Model {
    String name;
    String script_file;
    boolean active;
    ModelType type;
    Conversation data;

    public ChatModelDummy(String name, String script, boolean active) {
        this.name = name;
        this.script_file = script;
        this.active = active;
        this.type = ModelType.DECOM_REFACTOR;
    }

    public String get_name() {
        return name;
    }

    public void set_name(String name) {
        this.name = name;
    }

    public String get_script() {
        return script_file;
    }

    public void set_script(String script_file) {
        this.script_file = script_file;
    }

    public boolean get_active() {
        return active;
    }

    public void set_active(boolean b) {
        this.active = b;
    }

    public ModelType get_type() {
        return type;
    }

    public void set_type(ModelType type) {
        this.type = type;
    }

    public Conversation guess(Conversation convo, KinGAidraDecomTaskService service,
            PluginTool tool, Program program) {
        convo.add_assistant_msg(convo.get_msg(convo.get_msgs_len() - 1) + "_response");
        return convo;
    }
}