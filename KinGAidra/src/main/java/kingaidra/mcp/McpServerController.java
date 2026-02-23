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
    private static final String MCP_URL_PATH = "/mcp";
    private static final long MCP_URL_POLL_INTERVAL_MS = 100L;

    private final Object lock = new Object();
    private TaskMonitorAdapter monitor;
    private Program program;
    private String server_url;
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
        stop_server();
        synchronized (lock) {
            this.program = program;
            this.server_url = null;
        }
        if (!is_auto_start_enabled()) {
            return;
        }
        start_server();
    }

    public void on_program_closed() {
        stop_server();
        synchronized (lock) {
            program = null;
            server_url = null;
        }
    }

    public boolean start_server() {
        Program run_program;
        TaskMonitorAdapter current_monitor;
        synchronized (lock) {
            if (is_running_locked()) {
                return false;
            }
            run_program = program;
            if (run_program == null) {
                return false;
            }
            current_monitor = new TaskMonitorAdapter(true);
            monitor = current_monitor;
            server_url = null;
        }

        Thread start_thread = new Thread(() -> {
            try {
                new GhidraUtilImpl(run_program, current_monitor).run_script(MCP_SCRIPT_NAME, current_monitor);
            } finally {
                synchronized (lock) {
                    if (monitor == current_monitor) {
                        monitor = null;
                        server_url = null;
                    }
                }
            }
        }, "KinGAidra-MCP-" + run_program.getName());
        start_thread.setDaemon(true);
        start_thread.start();
        return true;
    }

    public boolean stop_server() {
        TaskMonitorAdapter current_monitor;
        synchronized (lock) {
            current_monitor = monitor;
            monitor = null;
            server_url = null;
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

    public String get_server_url() {
        synchronized (lock) {
            return server_url;
        }
    }

    public String ensure_server_url() {
        start_server();
        long wait_ms = 10 * 1000;
        long deadline = System.currentTimeMillis() + wait_ms;
        while (true) {
            String url = get_server_url();
            if (url != null) {
                return url;
            }
            if (System.currentTimeMillis() > deadline) {
                return null;
            }
            try {
                Thread.sleep(MCP_URL_POLL_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
            if (!is_running()) {
                start_server();
            }
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

    public void publish_server_url(String host, int port) {
        String url = build_server_url(host, port);
        synchronized (lock) {
            server_url = url;
        }
    }

    private String build_server_url(String host, int port) {
        return "http://" + host + ":" + port + MCP_URL_PATH;
    }
}
