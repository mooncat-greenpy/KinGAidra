package kingaidra;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import kingaidra.chat.Conversation;
import kingaidra.chat.KinGAidraChatTaskService;

//@formatter:off
@PluginInfo(
    status = PluginStatus.UNSTABLE,
    packageName = ExamplesPluginPackage.NAME,
    category = PluginCategoryNames.EXAMPLES,
    shortDescription = "AI-powered Ghidra extension for enhanced analysis.",
    description = "",
    servicesProvided = { KinGAidraChatTaskService.class },
    servicesRequired = {}
)
//@formatter:on
public class KinGAidraChatPlugin extends ProgramPlugin implements KinGAidraChatTaskService {

    private final String NAME = "KinGAidraChat";

    private Map<String, TaskStatus> status_map;
    private Map<String, Conversation> convo_map;

    public KinGAidraChatPlugin(PluginTool tool) {
        super(tool);

        status_map = new HashMap<>();
        convo_map = new HashMap<>();
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    public void add_task(String key, Conversation convo) {
        status_map.put(key, TaskStatus.RUNNING);
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
    public TaskStatus get_task_status(String key) {
        return status_map.get(key);
    }

    @Override
    public Conversation pop_task(String key) {
        Conversation convo = get_task(key);
        status_map.remove(key);
        convo_map.remove(key);
        return convo;
    }
}
