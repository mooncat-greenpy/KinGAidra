package kingaidra.decom.ai;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.KinGAidraDecomTaskService;

public interface Model {
    public String get_name();

    public String get_script();

    public DecomDiff guess(DecomDiff diff, KinGAidraDecomTaskService service, PluginTool tool,
            Program program);
}
