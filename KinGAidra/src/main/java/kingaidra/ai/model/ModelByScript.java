package kingaidra.ai.model;

import java.io.PrintWriter;
import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import com.fasterxml.jackson.databind.ObjectMapper;

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.app.services.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.Message;
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
            PluginTool tool, Program program, GhidraState src_state) {
        if (!active) {
            return null;
        }
        Logger logger = new Logger(tool, true);

        Random rand = new Random();
        String key = String.format("%x", rand.nextLong());

        convo.set_model(this);

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
        String assistant_response = null;
        try {
            GhidraState state;
            if (tool == null) {
                state = new GhidraState(src_state);
            } else {
                state = new GhidraState(tool, tool.getProject(), program, null, null, null);
            }

            ObjectMapper obj_mapper = new ObjectMapper();
            List<Message> msgs = new LinkedList<>();
            for (int i = 0; i < convo.get_msgs_len(); i++) {
                msgs.add(new Message(convo.get_role(i), convo.get_msg(i)));
            }
            state.addEnvironmentVar("KEY", key);
            state.addEnvironmentVar("TYPE", task_type.toString());
            state.addEnvironmentVar("MESSAGES", obj_mapper.writeValueAsString(msgs));

            script.set(state, TaskMonitor.DUMMY, writer);
            String[] args = {key};
            script.runScript(script_file, args);

            assistant_response = (String) state.getEnvironmentVar("RESPONSE");
        } catch (Exception e) {
            logger.append_message(String.format("Failed to run script \"%s\"", script_file));
            return null;
        }

        if (assistant_response == null) {
            return null;
        }
        convo.add_msg(Conversation.ASSISTANT_ROLE, assistant_response);
        return convo;
    }
}
