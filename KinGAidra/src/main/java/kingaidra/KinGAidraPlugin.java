package kingaidra;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitorAdapter;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.ai.task.TaskStatus;
import kingaidra.ai.task.TaskType;
import kingaidra.gui.MainProvider;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.log.Logger;
import kingaidra.ghidra.PromptConf;

import ghidra.framework.options.Options;
import ghidra.framework.options.OptionType;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "AI-powered Ghidra extension for enhanced analysis.",
    description = "KinGAidra is a Ghidra extension designed to enhance reverse engineering workflows by integrating AI capabilities. " +
                  "It helps analysts understand binaries more efficiently.",
    servicesProvided = { KinGAidraChatTaskService.class },
    servicesRequired = { GoToService.class }
)
//@formatter:on
public class KinGAidraPlugin extends ProgramPlugin implements KinGAidraChatTaskService {

    private static final String NAME = "KinGAidra";
    private static final String OPTIONS_ROOT = "KingAidra";
    private static final String MCP_OPTIONS_ROOT = "MCP";
    private static final String OPTION_MCP_AUTO_START = "Auto-start MCP server";
    private static final boolean DEFAULT_MCP_AUTO_START = true;
    private static final String MCP_SCRIPT_NAME = "kingaidra_mcp.py";

    private MainProvider provider;
    private Logger logger;
    private PromptConf prompts;
    private Options options;
    private final Object mcp_lock = new Object();
    private TaskMonitorAdapter mcp_monitor;

    public KinGAidraPlugin(PluginTool tool) {
        super(tool);

        logger = new Logger(tool, true);
        prompts = new PromptConf();

        options = tool.getOptions(OPTIONS_ROOT);
        prompts.bind_options(options);
        register_prompt_options(options);
        register_mcp_options(options);

        status_map = new HashMap<>();
        type_map = new HashMap<>();
        convo_map = new HashMap<>();
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    public void programOpened(Program program) {
        provider = new MainProvider(program, this, NAME, null, logger, prompts);

        String topicName = "kingaidra";
        String anchorName = "HelpAnchor";
        provider.setHelpLocation(new HelpLocation(topicName, anchorName));

        auto_start_mcp_server(program);
    }

    @Override
    public void programClosed(Program program) {
        stop_mcp_server();
        super.programClosed(program);
    }


    private Map<String, TaskStatus> status_map;
    private Map<String, TaskType> type_map;
    private Map<String, Conversation> convo_map;

    @Override
    public void add_task(String key, TaskType type, Conversation convo) {
        status_map.put(key, TaskStatus.RUNNING);
        type_map.put(key, type);
        convo_map.put(key, convo);
    }

    @Override
    public void commit_task(String key, String msg) {
        Conversation convo = convo_map.get(key);
        convo.add_assistant_msg(msg);
        status_map.put(key, TaskStatus.SUCCESS);
        convo_map.put(key, convo);
    }

    @Override
    public void commit_task_error(String key, String err_msg) {
        status_map.put(key, TaskStatus.FAILED);
    }

    @Override
    public Conversation get_task(String key) {
        return convo_map.get(key);
    }

    @Override
    public TaskType get_task_type(String key) {
        return type_map.get(key);
    }

    @Override
    public TaskStatus get_task_status(String key) {
        return status_map.get(key);
    }

    @Override
    public Conversation pop_task(String key) {
        Conversation convo = get_task(key);
        status_map.remove(key);
        type_map.remove(key);
        convo_map.remove(key);
        return convo;
    }

    private void register_prompt_options(Options options) {
        Options prompt_root = options.getOptions(PromptConf.PROMPT_OPTIONS_ROOT);
        prompt_root.registerOption(
            PromptConf.OPTION_SYSTEM_PROMPT,
            OptionType.STRING_TYPE,
            prompts.get_default_system_prompt_base(),
            null,
            "System prompt used for all tasks.",
            () -> new MultiLineStringPropertyEditor()
        );

        for (TaskType task : TaskType.values()) {
            Options group_options = PromptConf.get_group_options(
                prompt_root,
                PromptConf.get_user_prompt_group_path(task)
            );
            group_options.registerOption(
                PromptConf.get_user_prompt_option_name(task),
                OptionType.STRING_TYPE,
                prompts.get_default_user_prompt(task),
                null,
                PromptConf.get_user_prompt_description(task),
                () -> new MultiLineStringPropertyEditor()
            );
        }
    }

    private void register_mcp_options(Options options) {
        Options mcp_root = options.getOptions(MCP_OPTIONS_ROOT);
        mcp_root.registerOption(
            OPTION_MCP_AUTO_START,
            OptionType.BOOLEAN_TYPE,
            DEFAULT_MCP_AUTO_START,
            null,
            "Automatically start kingaidra_mcp.py when a program opens."
        );
    }

    private boolean is_mcp_auto_start_enabled() {
        if (options == null) {
            return DEFAULT_MCP_AUTO_START;
        }
        Options mcp_root = options.getOptions(MCP_OPTIONS_ROOT);
        return mcp_root.getBoolean(OPTION_MCP_AUTO_START, DEFAULT_MCP_AUTO_START);
    }

    public boolean start_mcp_server(Program program) {
        if (program == null) {
            return false;
        }
        synchronized (mcp_lock) {
            if (mcp_monitor != null && !mcp_monitor.isCancelled()) {
                return false;
            }
            mcp_monitor = new TaskMonitorAdapter(true);
        }

        Thread start_thread = new Thread(() -> {
            TaskMonitorAdapter monitor;
            synchronized (mcp_lock) {
                monitor = mcp_monitor;
            }
            if (monitor == null) {
                return;
            }
            try {
                new GhidraUtilImpl(program, monitor).run_script(MCP_SCRIPT_NAME, monitor);
            } finally {
                synchronized (mcp_lock) {
                    if (mcp_monitor == monitor) {
                        mcp_monitor = null;
                    }
                }
            }
        }, "KinGAidra-MCP-" + program.getName());
        start_thread.setDaemon(true);
        start_thread.start();
        return true;
    }

    public boolean stop_mcp_server() {
        TaskMonitorAdapter monitor;
        synchronized (mcp_lock) {
            monitor = mcp_monitor;
            mcp_monitor = null;
        }
        if (monitor != null) {
            monitor.cancel();
            return true;
        }
        return false;
    }

    public boolean is_mcp_running() {
        synchronized (mcp_lock) {
            return mcp_monitor != null && !mcp_monitor.isCancelled();
        }
    }

    private void auto_start_mcp_server(Program program) {
        if (!is_mcp_auto_start_enabled()) {
            return;
        }
        start_mcp_server(program);
    }
}
