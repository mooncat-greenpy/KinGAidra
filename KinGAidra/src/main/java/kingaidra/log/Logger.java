package kingaidra.log;

import java.io.PrintWriter;

import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;

public class Logger {
    private PluginTool tool;
    private PrintWriter writer;
    private boolean mode;

    public Logger(PluginTool t, boolean debugmode) {
        set_logger(t, debugmode);
    }

    private PrintWriter get_writer() {
        if (tool == null) {
            return null;
        }
        ConsoleService console = tool.getService(ConsoleService.class);
        if (console == null) {
            return null;
        }
        return console.getStdOut();
    }

    public void set_logger(PluginTool tool, boolean debugmode) {
        this.tool = tool;
        this.mode = debugmode;
    }

    public void append_message(String str) {
        if (!mode) {
            return;
        }

        if (writer == null) {
            writer = get_writer();
            if (writer == null) {
                return;
            }
        }
        writer.append(str + "\n");
    }
}
