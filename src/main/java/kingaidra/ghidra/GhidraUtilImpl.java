package kingaidra.ghidra;

import java.util.Iterator;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.DiffPair;
import kingaidra.log.Logger;

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
            if (service == null) {
                continue;
            }
            return service.getCurrentLocation().getAddress();
        }
        Logger.append_message("Failed to get selected address");
        return null;
    }

    public Address get_addr(long addr_value) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_value);
    }

    public Function get_func(Address addr) {
        Function func = program_listing.getFunctionContaining(addr);
        if (func == null) {
            Logger.append_message("Failed to get function");
        }
        return func;
    }

    private DecompileResults get_decom_results(Function func) {
        DecompInterface decom_interface = new DecompInterface();
        decom_interface.openProgram(program);
        return decom_interface.decompileFunction(func, 0, monitor);
    }

    private HighFunction get_high_func(Function func) {
        DecompileResults decom_result = get_decom_results(func);
        HighFunction hfunc = decom_result.getHighFunction();
        if (hfunc == null) {
            Logger.append_message("Failed to get decompiled function");
        }
        return hfunc;
    }

    public String get_decom(Address addr) {
        Function func = get_func(addr);
        if (func == null) {
            return null;
        }
        DecompileResults decom_result = get_decom_results(func);
        DecompiledFunction decom_func = decom_result.getDecompiledFunction();
        if (decom_func == null) {
            Logger.append_message("Failed to get decompiled function");
            return null;
        }
        return decom_func.getC();
    }

    public DecomDiff get_decomdiff(Address addr) {
        Function func = get_func(addr);
        if (func == null) {
            return null;
        }
        HighFunction high_func = get_high_func(func);
        if (high_func == null) {
            return null;
        }
        String src_code = get_decom(addr);
        if (src_code == null) {
            return null;
        }

        DecomDiff decom_diff = new DecomDiff(func.getEntryPoint(), func.getName(), src_code);
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
        Function func = get_func(diff.get_addr());
        if (func == null) {
            Logger.append_message(
                    String.format("Failed to find func %x", diff.get_addr().getOffset()));
            return false;
        }

        int tid = program.startTransaction("KinGAidra decompiler");
        try {
            try {
                func.setName(diff.get_name().get_new_name(), SourceType.USER_DEFINED);
            } catch (DuplicateNameException | InvalidInputException e) {
                Logger.append_message(String.format("Failed to rename func name \"%s\" to \"%s\"",
                        diff.get_name().get_old_name(), diff.get_name().get_new_name()));
            }

            for (DiffPair pair : diff.get_params()) {
                Parameter param = func.getParameter((int) pair.get_id());
                if (param == null) {
                    Logger.append_message(
                            String.format("Failed to find param \\\"%s\\\"", pair.get_old_name()));
                }
                try {
                    param.setName(pair.get_new_name(), SourceType.USER_DEFINED);
                } catch (DuplicateNameException | InvalidInputException e) {
                    Logger.append_message(
                            String.format("Failed to rename param name \\\"%s\\\" to \\\"%s\\\"",
                                    pair.get_old_name(), pair.get_new_name()));
                }
            }

            HighFunction high_func = get_high_func(func);
            if (high_func == null) {
                Logger.append_message("Failed to get vars");
            } else {
                for (DiffPair pair : diff.get_vars()) {
                    HighSymbol sym = high_func.getLocalSymbolMap().getSymbol(pair.get_id());
                    if (sym == null) {
                        Logger.append_message(String.format("Failed to find var name \\\"%s\\\"",
                                pair.get_old_name()));
                    }
                    try {
                        HighFunctionDBUtil.updateDBVariable(sym, pair.get_new_name(), null,
                                SourceType.USER_DEFINED);
                    } catch (InvalidInputException | DuplicateNameException e) {
                        Logger.append_message(
                                String.format("Failed to rename var name \\\"%s\\\" to \\\"%s\\\"",
                                        pair.get_old_name(), pair.get_new_name()));
                    }
                }
            }

        } finally {
            program.endTransaction(tid, true);
        }
        return true;
    }
}
