package kingaidra.decom.ai;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.KinGAidraDecomTaskService;

public class ModelByScript implements Model {
    private String name;
    private String script_file;

    public ModelByScript(String name, String script) {
        this.name = name;
        this.script_file = script;
    }

    public String get_name() {
        return name;
    }

    public String get_script() {
        return script_file;
    }

    public DecomDiff guess(DecomDiff diff, KinGAidraDecomTaskService service, PluginTool tool,
            Program program) {
        return diff;
    }
}
