package kingaidra.chat.ai;

import java.io.PrintWriter;
import java.util.Random;

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.app.services.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.chat.Conversation;
import kingaidra.decom.ai.ModelType;
import kingaidra.decom.KinGAidraDecomTaskService;
import kingaidra.log.Logger;

public class ModelByScript implements Model {
    private String name;
    private String script_file;
    private boolean active;
    private ModelType type;

    public ModelByScript(String name, String script, boolean active) {
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

    public Conversation guess(Conversation convo, KinGAidraDecomTaskService service, PluginTool tool,
            Program program) {
        return convo;
    }
}
