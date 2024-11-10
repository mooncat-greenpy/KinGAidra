package kingaidra.decom.ai;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.KinGAidraDecomTaskService;

public interface Model {
    public String get_name();

    public void set_name(String name);

    public String get_script();

    public void set_script(String script_file);

    public boolean get_active();

    public void set_active(boolean b);

    public DecomDiff guess(DecomDiff diff, KinGAidraDecomTaskService service, PluginTool tool,
            Program program);
}
