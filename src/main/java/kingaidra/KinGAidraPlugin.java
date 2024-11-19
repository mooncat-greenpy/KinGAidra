package kingaidra;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.KinGAidraDecomTaskService;
import kingaidra.chat.KinGAidraChatTaskService;
import kingaidra.gui.MainProvider;
import kingaidra.log.Logger;

//@formatter:off
@PluginInfo(
    status = PluginStatus.UNSTABLE,
    packageName = ExamplesPluginPackage.NAME,
    category = PluginCategoryNames.EXAMPLES,
    shortDescription = "AI-powered Ghidra extension for enhanced analysis.",
    description = "KinGAidra is a Ghidra extension that uses AI to enhance reverse engineering by refining decompilation results. " +
                  "It provides tools for refactoring the decompiled code, making it easier to analyze and understand.",
    servicesProvided = { KinGAidraDecomTaskService.class },
    servicesRequired = {}
)
//@formatter:on
public class KinGAidraPlugin extends ProgramPlugin implements KinGAidraDecomTaskService {

    private final String NAME = "KinGAidra";
    MainProvider provider;

    public KinGAidraPlugin(PluginTool tool) {
        super(tool);

        Logger.set_logger(tool, false);

        status_map = new HashMap<>();
        diff_map = new HashMap<>();
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    public void programOpened(Program program) {
        KinGAidraChatTaskService service = null;
        for (Object obj : program.getConsumerList()) {
            if (!(obj instanceof PluginTool)) {
                continue;
            }
            PluginTool plugin_tool = (PluginTool) obj;
            service = plugin_tool.getService(KinGAidraChatTaskService.class);
            break;
        }
        provider = new MainProvider(program, this, NAME, this, service);

        String topicName = "kingaidra";
        String anchorName = "HelpAnchor";
        provider.setHelpLocation(new HelpLocation(topicName, anchorName));
    }


    private Map<String, TaskStatus> status_map;
    private Map<String, DecomDiff> diff_map;

    @Override
    public void add_task(String key, DecomDiff diff) {
        status_map.put(key, TaskStatus.RUNNING);
        diff_map.put(key, diff);
    }

    @Override
    public void commit_task(String key, String func_name, Map<String, String> params,
            Map<String, String> vars, Map<String, String> datatypes) {
        DecomDiff diff = diff_map.get(key);
        diff.set_name(func_name);
        for (String p_key : params.keySet()) {
            diff.set_param_new_name(p_key, params.get(p_key));
        }
        for (String v_key : vars.keySet()) {
            diff.set_var_new_name(v_key, vars.get(v_key));
        }
        for (String v_key : datatypes.keySet()) {
            diff.set_datatype_new_name(v_key, datatypes.get(v_key));
        }
        status_map.put(key, TaskStatus.SUCCESS);
        diff_map.put(key, diff);
    }

    @Override
    public void commit_task_error(String key, String err_msg) {
        status_map.put(key, TaskStatus.FAILED);
    }

    @Override
    public DecomDiff get_task(String key) {
        return diff_map.get(key);
    }

    @Override
    public TaskStatus get_task_status(String key) {
        return status_map.get(key);
    }

    @Override
    public DecomDiff pop_task(String key) {
        DecomDiff diff = get_task(key);
        status_map.remove(key);
        diff_map.remove(key);
        return diff;
    }
}
