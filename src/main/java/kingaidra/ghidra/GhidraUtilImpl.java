package kingaidra.ghidra;

import java.util.Iterator;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.util.task.TaskMonitor;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.DiffPair;

public class GhidraUtilImpl implements GhidraUtil {
    private Program program;
    private TaskMonitor monitor;
    private Listing program_listing;

    public GhidraUtilImpl(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
        this.program_listing = program.getListing();
    }

    public Address get_current_addr() {
        for (Object obj : program.getConsumerList()) {
            if (!(obj instanceof PluginTool)) {
                continue;
            }
            PluginTool plugin_tool = (PluginTool) obj;
            CodeViewerService service = plugin_tool.getService(CodeViewerService.class);
            return service.getCurrentLocation().getAddress();
        }
        return null;
    }

    public Function get_func(Address addr) {
        return program_listing.getFunctionContaining(addr);
    }

    private DecompileResults get_decom_results(Function func) {
        DecompInterface decom_interface = new DecompInterface();
        decom_interface.openProgram(program);
        return decom_interface.decompileFunction(func, 0, monitor);
    }

    private HighFunction get_high_func(Function func) {
        DecompileResults decom_result = get_decom_results(func);
        return decom_result.getHighFunction();
    }

    public String get_decom(Address addr) {
        Function func = get_func(addr);
        if (func == null) {
            return null;
        }
        DecompileResults decom_result = get_decom_results(func);
        return decom_result.getDecompiledFunction().getC();
    }

    public DecomDiff get_decomdiff(Address addr) {
        Function func = get_func(addr);
        if (func == null) {
            return null;
        }
        HighFunction high_func = get_high_func(func);

        DecomDiff decom_diff = new DecomDiff(func.getEntryPoint(), func.getName(), get_decom(addr));
        for (int i = 0; i < func.getParameterCount(); i++) {
            Parameter param = func.getParameter(i);
            DiffPair diff = new DiffPair(i, param.getName());
            decom_diff.add_param(diff);
        }
        for (Iterator<HighSymbol> itr = high_func.getLocalSymbolMap().getSymbols(); itr
                .hasNext();) {
            HighSymbol sym = itr.next();
            if (decom_diff.get_params().stream()
                    .anyMatch(p -> p.get_old_name().equals(sym.getName()))) {
                continue;
            }
            DiffPair diff = new DiffPair(sym.getId(), sym.getName());
            decom_diff.add_var(diff);
        }
        return decom_diff;
    }

    public boolean refact(DecomDiff diff) {
        return false;
    }
}
