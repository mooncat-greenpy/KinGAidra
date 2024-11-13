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

    public KinGAidraChatPlugin(PluginTool tool) {
        super(tool);

        convo_map = new HashMap<>();
    }

    @Override
    public void init() {
        super.init();
    }

    private Map<String, Conversation> convo_map;

    @Override
    public void add_task(String key, Conversation convo) {
        convo_map.put(key, convo);
    }

    @Override
    public void commit_task(String key, String msg) {
        Conversation convo = convo_map.get(key);
        convo.add_assistant_msg(msg);
        convo_map.put(key, convo);
    }

    @Override
    public Conversation get_task(String key) {
        return convo_map.get(key);
    }

    @Override
    public Conversation pop_task(String key) {
        Conversation convo = get_task(key);
        convo_map.remove(key);
        return convo;
    }
}
