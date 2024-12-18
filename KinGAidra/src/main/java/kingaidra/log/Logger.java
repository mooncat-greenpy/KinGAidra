package kingaidra.log;

import java.io.PrintWriter;

import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;

public class Logger {
    static PluginTool tool = null;
    static PrintWriter writer = null;
    static boolean mode = false;

    private Logger(PluginTool t, boolean debugmode) {
        tool = t;
        mode = debugmode;
    }

    private static PrintWriter get_writer() {
        if (tool == null) {
            return null;
        }
        ConsoleService console = tool.getService(ConsoleService.class);
        if (console == null) {
            return null;
        }
        return console.getStdOut();
    }

    public static void set_logger(PluginTool tool, boolean debugmode) {
        new Logger(tool, debugmode);
    }

    public static void append_message(String str) {
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
