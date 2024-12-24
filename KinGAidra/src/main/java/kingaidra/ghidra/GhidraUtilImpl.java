package kingaidra.ghidra;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.cparser.C.CParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
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

    public List<Function> get_func(String name) {
        List<Function> func_list = program_listing.getGlobalFunctions(name);
        for (Function func : program_listing.getExternalFunctions()) {
            if (func.getName().equals(name)) {
                func_list.add(func);
            }
        }
        return func_list;
    }

    public void get_root_func(List<Function> root) {
        FunctionIterator itr = program_listing.getFunctions(true);
        while (itr.hasNext()) {
            add_root_func(itr.next(), root, new HashSet<>());
        }
    }

    private void add_root_func(Function target, List<Function> root, Set<Function> visited) {
        if (visited.contains(target)) {
            return;
        }
        visited.add(target);
        Set<Function> calling_set = target.getCallingFunctions(monitor);
        if (calling_set.isEmpty() && !root.contains(target)) {
            root.add(target);
            return;
        }
        for (Function calling : calling_set) {
            add_root_func(calling, root, visited);
        }
        root.forEach(Function::getEntryPoint);
    }

    private void build_call_tree_str(Function func, int indent, Set<Long> visited, StringBuilder call_tree) {
        Stack<Function> func_stack = new Stack<>();
        Stack<Integer> indent_stack = new Stack<>();
        func_stack.push(func);
        indent_stack.push(indent);

        while (!func_stack.isEmpty()) {
            Function cur_func = func_stack.pop();
            int cur_indent = indent_stack.pop();

            if (visited.contains(cur_func.getEntryPoint().getOffset())) {
                continue;
            }
            visited.add(cur_func.getEntryPoint().getOffset());

            call_tree.append("    ".repeat(cur_indent)).append("- ").append(cur_func.getName()).append("\n");

            Set<Function> called_set = cur_func.getCalledFunctions(monitor);
            List<Function> called_list = new ArrayList<>(called_set);
            Collections.sort(called_list, new Comparator<Function>() {
                @Override
                public int compare(Function o1, Function o2) {
                    return o2.getEntryPoint().compareTo(o1.getEntryPoint());
                }
            });
            for (Function called : called_list) {
                func_stack.push(called);
                indent_stack.push(cur_indent + 1);
            }
        }
    }

    public String get_func_call_tree() {
        List<Function> root = new LinkedList<>();
        get_root_func(root);
        String call_tree = "";
        for (Function func : root) {
            call_tree += get_func_call_tree(func);
        }
        return call_tree;
    }

    public String get_func_call_tree(Function func) {
        StringBuilder call_tree = new StringBuilder();
        build_call_tree_str(func, 0, new HashSet<>(), call_tree);
        return call_tree.toString();
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
            String comment = "";

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
                Reference[] refs = inst.getOperandReferences(i);
                for (Reference ref : refs) {
                    if (ref.getReferenceType() == RefType.DATA) {
                        Address to = ref.getToAddress();
                        Data data = get_data(to);
                        if (data != null && data.getValueClass() == String.class) {
                            comment += String.format("[%x]=\"%s\" ", to.getOffset(), (String) data.getValue());
                        }
                    }
                }
            }

            SymbolTable label_sym_table = program.getSymbolTable();
            Symbol label_sym = label_sym_table.getPrimarySymbol(inst.getAddress());
            if (label_sym != null) {
                result += label_sym.getName() + ":\n";
            }
            result += "    " + asm + (comment.isEmpty()?"":(" ; " + comment)) + "\n";

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

    public void find_datatypes(String name, List<DataType> dt_list) {
        DataTypeManager datatype_manager = program.getDataTypeManager();
        datatype_manager.findDataTypes(name, dt_list);
    }

    public void add_datatype(DataType dt) {
        DataTypeManager datatype_manager = program.getDataTypeManager();
        int tid = program.startTransaction("KinGAidra datatype");
        try {
            CategoryPath category_path = new CategoryPath("/KinGAidra");
            Category category;
            if (datatype_manager.containsCategory(category_path)) {
                category = datatype_manager.getCategory(category_path);
            } else {
                category = datatype_manager.createCategory(category_path);
            }
            category.addDataType(dt, null);
        } finally {
            program.endTransaction(tid, true);
        }
    }

    public DataType parse_datatypes(String code) {
        String regex = "#define\\s+(\\S+)\\s+(\\S+)";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(code);
        while (matcher.find()) {
            String define = matcher.group(0);
            String key = matcher.group(1);
            String value = matcher.group(2);
            code = code.replace(define, "");
            code = code.replace(key, value);
        }

        DataTypeManager datatype_manager = program.getDataTypeManager();
        CParser parser = new CParser(datatype_manager);
        DataType dt;
        try {
            dt = parser.parse(code);
        } catch (Exception e) {
            return null;
        }
        return dt;
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
                        diff.get_name().get_var_name(), diff.get_name().get_new_name()));
            }

            for (int i = func.getParameterCount() - 1; i >= 0 ; i--) {
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
                        find_datatypes(datatype_pair.get_new_name(), dt_l);
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

            List<DiffPair> reverse_vars = new LinkedList<>();
            for (DiffPair pair : diff.get_vars()) {
                reverse_vars.add(pair);
            }
            Collections.reverse(reverse_vars);
            for (DiffPair pair : reverse_vars) {
                HighFunction high_func = get_high_func(func);
                if (high_func == null) {
                    Logger.append_message("Failed to get vars");
                    break;
                }
                HighSymbol sym = high_func.getLocalSymbolMap().getSymbol(pair.get_id());
                if (sym == null) {
                    continue;
                }

                String new_name = pair.get_new_name();

                DiffPair datatype_pair = diff.get_datatype(sym.getId());
                DataType new_dt = null;
                if (datatype_pair != null) {
                    List<DataType> dt_l = new LinkedList<>();
                    find_datatypes(diff.get_datatype(datatype_pair.get_id()).get_new_name(),
                            dt_l);
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
                                    pair.get_var_name(), pair.get_new_name()));
                }
            }
        } finally {
            program.endTransaction(tid, true);
        }
        return true;
    }

    public Data get_data(Address addr) {
        Memory memory = program.getMemory();
        DataTypeManager datatype_manager = program.getDataTypeManager();

        try {
            return program_listing.getDataAt(addr);
        } catch (Exception e) {
            return null;
        }
    }
}
