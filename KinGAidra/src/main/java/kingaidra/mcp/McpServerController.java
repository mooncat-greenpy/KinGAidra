package kingaidra.mcp;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitorAdapter;
import kingaidra.ghidra.GhidraUtilImpl;

public class McpServerController {
    private static final String MCP_OPTIONS_ROOT = "MCP";
    private static final String OPTION_MCP_AUTO_START = "Auto-start MCP server";
    private static final boolean DEFAULT_MCP_AUTO_START = true;
    private static final String MCP_SCRIPT_NAME = "kingaidra_mcp.py";

    private final Object lock = new Object();
    private TaskMonitorAdapter monitor;
    private Options options;

    public void register_options(Options options) {
        this.options = options;
        Options mcp_root = options.getOptions(MCP_OPTIONS_ROOT);
        mcp_root.registerOption(
            OPTION_MCP_AUTO_START,
            OptionType.BOOLEAN_TYPE,
            DEFAULT_MCP_AUTO_START,
            null,
            "Automatically start kingaidra_mcp.py when a program opens."
        );
    }

    public void on_program_opened(Program program) {
        if (!is_auto_start_enabled()) {
            return;
        }
        start_server(program);
    }

    public void on_program_closed() {
        stop_server();
    }

    public boolean start_server(Program program) {
        if (program == null) {
            return false;
        }

        TaskMonitorAdapter current_monitor = new TaskMonitorAdapter(true);
        synchronized (lock) {
            if (is_running_locked()) {
                return false;
            }
            monitor = current_monitor;
        }

        Thread start_thread = new Thread(() -> {
            try {
                new GhidraUtilImpl(program, current_monitor).run_script(MCP_SCRIPT_NAME, current_monitor);
            } finally {
                synchronized (lock) {
                    if (monitor == current_monitor) {
                        monitor = null;
                    }
                }
            }
        }, "KinGAidra-MCP-" + program.getName());
        start_thread.setDaemon(true);
        start_thread.start();
        return true;
    }

    public boolean stop_server() {
        TaskMonitorAdapter current_monitor;
        synchronized (lock) {
            current_monitor = monitor;
            monitor = null;
        }
        if (current_monitor == null) {
            return false;
        }
        current_monitor.cancel();
        return true;
    }

    public boolean is_running() {
        synchronized (lock) {
            return is_running_locked();
        }
    }

    private boolean is_auto_start_enabled() {
        if (options == null) {
            return DEFAULT_MCP_AUTO_START;
        }
        Options mcp_root = options.getOptions(MCP_OPTIONS_ROOT);
        return mcp_root.getBoolean(OPTION_MCP_AUTO_START, DEFAULT_MCP_AUTO_START);
    }

    private boolean is_running_locked() {
        return monitor != null && !monitor.isCancelled();
    }
}
