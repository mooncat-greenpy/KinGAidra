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

    private final String NAME = "KinGAidra";
    private MainProvider provider;
    private Logger logger;

    public KinGAidraPlugin(PluginTool tool) {
        super(tool);

        logger = new Logger(tool, true);

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
        provider = new MainProvider(program, this, NAME, null, logger);

        String topicName = "kingaidra";
        String anchorName = "HelpAnchor";
        provider.setHelpLocation(new HelpLocation(topicName, anchorName));
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
}
