package kingaidra.decom.ai;

import java.io.PrintWriter;
import java.util.Random;

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.app.services.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.KinGAidraDecomTaskService;
import kingaidra.log.Logger;

public class ModelByScript implements Model {
    private String name;
    private String script_file;
    private boolean active;

    public ModelByScript(String name, String script, boolean active) {
        this.name = name;
        this.script_file = script;
        this.active = active;
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

    public DecomDiff guess(DecomDiff diff, KinGAidraDecomTaskService service, PluginTool tool,
            Program program) {
        if (!active) {
            return diff;
        }

        Random rand = new Random();
        String key = String.format("%x", rand.nextLong());

        diff.set_model(this);
        service.add_task(key, diff);

        ResourceFile file = GhidraScriptUtil.findScriptByName(script_file);
        if (file == null) {
            Logger.append_message(String.format("Failed to get script \"%s\"", script_file));
            return diff;
        }
        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(file);
        if (provider == null) {
            Logger.append_message(String.format("Failed to get script \"%s\"", script_file));
            return diff;
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
            Logger.append_message(String.format("Failed to get script \"%s\"", script_file));
            return diff;
        }
        try {
            GhidraState state = new GhidraState(tool, tool.getProject(), program, null, null, null);
            state.addEnvironmentVar("KEY", key);
            script.set(state, TaskMonitor.DUMMY, writer);
            String[] args = {key};
            script.runScript(script_file, args);
        } catch (Exception e) {
            Logger.append_message(String.format("Failed to run script \"%s\"", script_file));
            return diff;
        }

        return service.pop_task(key);
    }
}
