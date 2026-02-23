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
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.ai.task.TaskStatus;
import kingaidra.ai.task.TaskType;
import kingaidra.gui.MainProvider;
import kingaidra.log.Logger;
import kingaidra.mcp.McpServerController;
import kingaidra.ghidra.PromptConf;

import ghidra.framework.options.Options;
import ghidra.framework.options.OptionType;
import ghidra.program.util.ProgramLocation;

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
    private static final String OPTIONS_ROOT = "KinGAidra";

    private MainProvider provider;
    private Logger logger;
    private PromptConf prompts;
    private McpServerController mcp_controller;

    public KinGAidraPlugin(PluginTool tool) {
        super(tool);

        logger = new Logger(tool, true);
        prompts = new PromptConf();

        Options options = tool.getOptions(OPTIONS_ROOT);
        prompts.bind_options(options);
        register_prompt_options(options);
        mcp_controller = new McpServerController();
        mcp_controller.register_options(options);

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

        mcp_controller.on_program_opened(program);
    }

    @Override
    public void programClosed(Program program) {
        mcp_controller.on_program_closed();
        super.programClosed(program);
    }

    @Override
    protected void locationChanged(ProgramLocation loc) {
        super.locationChanged(loc);
        if (provider != null) {
            provider.location_changed(loc);
        }
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

        Options workflow_options = PromptConf.get_group_options(
            prompt_root,
            PromptConf.get_workflow_group_path()
        );
        workflow_options.registerOption(
            PromptConf.OPTION_WORKFLOWS_JSON,
            OptionType.STRING_TYPE,
            prompts.get_default_workflows_json_base(),
            null,
            PromptConf.WORKFLOWS_DESCRIPTION,
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

    @Override
    public boolean start_mcp_server() {
        return mcp_controller.start_server();
    }

    @Override
    public boolean stop_mcp_server() {
        return mcp_controller.stop_server();
    }

    @Override
    public boolean is_mcp_running() {
        return mcp_controller.is_running();
    }

    @Override
    public String ensure_mcp_server_url() {
        return mcp_controller.ensure_server_url();
    }

    public String get_mcp_server_url() {
        return mcp_controller.get_server_url();
    }

    @Override
    public void publish_mcp_server_url(String host, int port) {
        mcp_controller.publish_server_url(host, port);
    }
}
