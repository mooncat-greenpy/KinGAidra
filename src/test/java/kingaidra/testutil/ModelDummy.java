package kingaidra.testutil;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.DiffPair;
import kingaidra.decom.KinGAidraDecomTaskService;
import kingaidra.decom.ai.Model;

public class ModelDummy implements Model {
    String name;
    String script_file;
    DecomDiff data;

    public ModelDummy(String name, String script) {
        this.name = name;
        this.script_file = script;
    }

    public String get_name() {
        return name;
    }

    public void set_name(String name) {
        this.name = name;
    }

    public String get_script() {
        return script_file;
    }

    public void set_script(String script_file) {
        this.script_file = script_file;
    }

    public DecomDiff guess(DecomDiff diff, KinGAidraDecomTaskService service, PluginTool tool,
            Program program) {
        diff.set_name(diff.get_name().get_new_name() + name);
        for (DiffPair pair : diff.get_params()) {
            pair.set_new_name(pair.get_new_name() + name);
        }
        for (DiffPair pair : diff.get_vars()) {
            pair.set_new_name(pair.get_new_name() + name);
        }
        return diff;
    }
}
