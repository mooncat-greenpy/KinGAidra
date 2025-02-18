package kingaidra.ai.model;

import java.io.PrintWriter;
import java.io.Serializable;
import java.util.Random;

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.app.services.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.ai.task.TaskStatus;
import kingaidra.ai.task.TaskType;
import kingaidra.log.Logger;

public class ModelByScript implements Model, Serializable {
    private String name;
    private String script_file;
    private boolean active;
    private ModelType type;

    public ModelByScript(String name, String script, boolean active) {
        this.name = name;
        this.script_file = script;
        this.active = active;
        this.type = ModelType.CHAT;
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

    public Conversation guess(TaskType task_type, Conversation convo, KinGAidraChatTaskService service,
            PluginTool tool, Program program) {
        if (!active) {
            return null;
        }
        Logger logger = new Logger(tool, true);

        Random rand = new Random();
        String key = String.format("%x", rand.nextLong());

        convo.set_model(this);
        service.add_task(key, task_type, convo);

        ResourceFile file = GhidraScriptUtil.findScriptByName(script_file);
        if (file == null) {
            logger.append_message(String.format("Failed to get script \"%s\"", script_file));
            return null;
        }
        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(file);
        if (provider == null) {
            logger.append_message(String.format("Failed to get script \"%s\"", script_file));
            return null;
        }
        PrintWriter writer;
        if (tool != null) {
            ConsoleService console = tool.getService(ConsoleService.class);
            if (console != null) {
                writer = console.getStdOut();
            } else {
                writer = new PrintWriter(System.out);
            }
        } else {
            writer = new PrintWriter(System.out);
        }

        GhidraScript script = null;
        try {
            script = provider.getScriptInstance(file, writer);
        } catch (Exception e) {
            logger.append_message(String.format("Failed to get script \"%s\"", script_file));
            return null;
        }
        try {
            GhidraState state = new GhidraState(tool, tool.getProject(), program, null, null, null);
            state.addEnvironmentVar("KEY", key);
            script.set(state, TaskMonitor.DUMMY, writer);
            String[] args = {key};
            script.runScript(script_file, args);
        } catch (Exception e) {
            logger.append_message(String.format("Failed to run script \"%s\"", script_file));
            return null;
        }

        if (service.get_task_status(key) != TaskStatus.SUCCESS) {
            return null;
        }

        return service.pop_task(key);
    }
}
