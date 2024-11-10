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
import kingaidra.gui.MainProvider;
import kingaidra.log.Logger;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = ExamplesPluginPackage.NAME,
    category = PluginCategoryNames.EXAMPLES,
    shortDescription = "Plugin short description goes here.",
    description = "Plugin long description goes here.",
    servicesProvided = { KinGAidraDecomTaskService.class },
    servicesRequired = {}
)
//@formatter:on
public class KinGAidraPlugin extends ProgramPlugin implements KinGAidraDecomTaskService {

    MainProvider provider;

    /**
     * Plugin constructor.
     * 
     * @param tool The plugin tool that this plugin is added to.
     */
    public KinGAidraPlugin(PluginTool tool) {
        super(tool);

        Logger.set_logger(tool, true);

        diff_map = new HashMap<>();
    }

    @Override
    public void init() {
        super.init();

        // TODO: Acquire services if necessary
    }

    @Override
    public void programOpened(Program program) {
        // TODO: Customize provider (or remove if a provider is not desired)
        String pluginName = getName();
        provider = new MainProvider(program, this, pluginName, this);

        // TODO: Customize help (or remove if help is not desired)
        String topicName = this.getClass().getPackage().getName();
        String anchorName = "HelpAnchor";
        provider.setHelpLocation(new HelpLocation(topicName, anchorName));
    }


    private Map<String, DecomDiff> diff_map;

    @Override
    public void add_task(String key, DecomDiff diff) {
        diff_map.put(key, diff);
    }

    @Override
    public void commit_task(String key, String func_name, Map<String, String> params,
            Map<String, String> vars) {
        DecomDiff diff = diff_map.get(key);
        diff.set_name(func_name);
        for (String p_key : params.keySet()) {
            diff.set_param_new_name(p_key, params.get(p_key));
        }
        for (String v_key : vars.keySet()) {
            diff.set_var_new_name(v_key, vars.get(v_key));
        }
        diff_map.put(key, diff);
    }

    @Override
    public DecomDiff get_task(String key) {
        return diff_map.get(key);
    }

    @Override
    public DecomDiff pop_task(String key) {
        DecomDiff diff = get_task(key);
        diff_map.remove(key);
        return diff;
    }
}
