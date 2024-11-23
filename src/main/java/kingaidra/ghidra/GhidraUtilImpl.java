package kingaidra.ghidra;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
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

    public String get_asm(Address addr) {
        String result = "";
        Function func = get_func(addr);
        if (func == null) {
            return null;
        }
        Address end_addr = func.getBody().getMaxAddress();

        Instruction inst = program_listing.getInstructionAt(func.getEntryPoint());
        while (inst.getAddress().getOffset() <= end_addr.getOffset()) {
            String asm = inst.toString();

            ReferenceManager ref_manager = program.getReferenceManager();
            for (Reference ref : ref_manager.getExternalReferences()) {
                ExternalReference ext_ref = (ExternalReference) ref;
                if (ext_ref.getExternalLocation() != null) {
                    if (ext_ref.getLabel() != null) {
                        asm = asm.replace("0x" + ext_ref.getFromAddress().toString(),
                                ext_ref.getExternalLocation().toString());
                    }
                }
            }

            for (int i = 0; i < inst.getNumOperands(); i++) {
                Object[] op_objs = inst.getOpObjects(i);
                for (Object obj : op_objs) {
                    if (obj instanceof Address) {
                        Address op_addr = (Address) obj;
                        SymbolTable sym_table = program.getSymbolTable();
                        Symbol sym = sym_table.getPrimarySymbol(op_addr);
                        if (sym != null) {
                            asm = asm.replace("0x" + op_addr.toString(), sym.getName());
                        }
                    }
                }
            }

            SymbolTable label_sym_table = program.getSymbolTable();
            Symbol label_sym = label_sym_table.getPrimarySymbol(inst.getAddress());
            if (label_sym != null) {
                result += label_sym.getName() + ":\n";
            }
            result += "    " + asm + "\n";

            inst = program_listing.getInstructionAfter(inst.getAddress());
        }
        return result;
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
            DiffPair dt_diff = new DiffPair(i, param.getName(), param.getDataType().getName());
            decom_diff.add_datatype(dt_diff);
        }
        for (Iterator<HighSymbol> itr = high_func.getLocalSymbolMap().getSymbols(); itr
                .hasNext();) {
            HighSymbol sym = itr.next();
            if (decom_diff.get_params().stream()
                    .anyMatch(p -> p.get_var_name().equals(sym.getName()))) {
                continue;
            }
            DiffPair diff = new DiffPair(sym.getId(), sym.getName());
            decom_diff.add_var(diff);
            DiffPair dt_diff =
                    new DiffPair(sym.getId(), sym.getName(), sym.getDataType().getName());
            decom_diff.add_datatype(dt_diff);
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

        DataTypeManager datatype_manager = program.getDataTypeManager();
        int tid = program.startTransaction("KinGAidra decompiler");
        try {
            try {
                func.setName(diff.get_name().get_new_name(), SourceType.USER_DEFINED);
            } catch (DuplicateNameException | InvalidInputException e) {
                Logger.append_message(String.format("Failed to rename func name \"%s\" to \"%s\"",
                        diff.get_name().get_var_name(), diff.get_name().get_new_name()));
            }

            for (int i = 0; i < func.getParameterCount(); i++) {
                Parameter param = func.getParameter(i);

                DiffPair param_pair = diff.get_param(i);
                if (param_pair != null) {
                    try {
                        param.setName(param_pair.get_new_name(), SourceType.USER_DEFINED);
                    } catch (DuplicateNameException | InvalidInputException e) {
                        Logger.append_message(String.format(
                                "Failed to rename param name \\\"%s\\\" to \\\"%s\\\"",
                                param_pair.get_var_name(), param_pair.get_new_name()));
                    }
                }

                DiffPair datatype_pair = diff.get_datatype(i);
                if (datatype_pair != null) {
                    try {
                        List<DataType> dt_l = new LinkedList<>();
                        datatype_manager.findDataTypes(datatype_pair.get_new_name(), dt_l);
                        if (dt_l.size() > 0) {
                            param.setDataType(dt_l.get(0), SourceType.USER_DEFINED);
                        }
                    } catch (InvalidInputException e) {
                        Logger.append_message(String.format(
                                "Failed to retype param name \\\"%s\\\" to \\\"%s\\\"",
                                datatype_pair.get_var_name(), datatype_pair.get_new_name()));
                    }
                }
            }

            HighFunction high_func = get_high_func(func);
            if (high_func == null) {
                Logger.append_message("Failed to get vars");
            } else {
                Iterator<HighSymbol> sym_itr = high_func.getLocalSymbolMap().getSymbols();
                while (sym_itr.hasNext()) {
                    HighSymbol sym = sym_itr.next();

                    DiffPair var_pair = diff.get_var(sym.getId());
                    String new_name = null;
                    if (var_pair != null) {
                        new_name = var_pair.get_new_name();
                    }

                    DiffPair datatype_pair = diff.get_datatype(sym.getId());
                    DataType new_dt = null;
                    if (datatype_pair != null) {
                        List<DataType> dt_l = new LinkedList<>();
                        datatype_manager.findDataTypes(
                                diff.get_datatype(datatype_pair.get_id()).get_new_name(), dt_l);
                        if (dt_l.size() > 0) {
                            new_dt = dt_l.get(0);
                        }
                    }

                    try {
                        HighFunctionDBUtil.updateDBVariable(sym, new_name, new_dt,
                                SourceType.USER_DEFINED);
                    } catch (InvalidInputException | DuplicateNameException e) {
                        Logger.append_message(
                                String.format("Failed to rename var name \\\"%s\\\" to \\\"%s\\\"",
                                        var_pair.get_var_name(), var_pair.get_new_name()));
                    }
                }
            }
        } finally {
            program.endTransaction(tid, true);
        }
        return true;
    }
}
