package kingaidra.decom.ai;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.KinGAidraDecomTaskService;

public class Ai {
    private PluginTool tool;
    private Program program;
    private KinGAidraDecomTaskService service;

    public Ai(PluginTool tool, Program program, KinGAidraDecomTaskService service) {
        this.tool = tool;
        this.program = program;
        this.service = service;
    }

    public DecomDiff guess(DecomDiff diff) {
        return diff.get_model().guess(diff, service, tool, program);
    }
}
