package kingaidra.testutil;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.DiffPair;
import kingaidra.decom.KinGAidraDecomTaskService;
import kingaidra.decom.ai.Model;
import kingaidra.decom.ai.ModelType;

public class ModelDummy implements Model {
    String name;
    String script_file;
    boolean active;
    ModelType type;
    DecomDiff data;

    public ModelDummy(String name, String script, boolean active) {
        this.name = name;
        this.script_file = script;
        this.active = active;
        this.type = ModelType.DECOM_REFACTOR;
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

    public boolean get_active() {
        return active;
    }

    public void set_active(boolean b) {
        this.active = b;
    }

    public ModelType get_type() {
        return type;
    }

    public void set_type(ModelType type) {
        this.type = type;
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
        for (DiffPair pair : diff.get_datatypes()) {
            pair.set_new_name(pair.get_new_name() + name);
        }
        return diff;
    }
}
