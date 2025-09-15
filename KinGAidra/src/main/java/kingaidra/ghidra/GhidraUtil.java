package kingaidra.ghidra;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import kingaidra.decom.DecomDiff;

public interface GhidraUtil {
    public Address get_current_addr();

    public Address get_addr(long addr_value);

    public Function get_func(Address addr);

    public List<Function> get_func(String name);

    public List<Reference> get_ref_to(Address addr);

    public List<Function> get_caller(Function func);

    public List<Function> get_callee(Function func);

    public void get_root_func(List<Function> root);

    public String get_func_call_tree();

    public String get_func_call_tree(Function func);

    public List<String> get_call_tree_parent(String call_tree, int depth, Function target);

    public List<String> get_call_tree_parent(String call_tree, int depth, String target);

    public Data[] get_strings();

    public String get_strings_str();

    public String get_strings_str(long index, long num);

    public String get_asm(Address addr);

    public String get_asm(Address addr, boolean include_addr);

    public String get_decom(Address addr);

    public DecomDiff get_decomdiff(Address addr);

    public void find_datatypes(String name, List<DataType> dt_list);

    public void add_datatype(DataType dt);

    public DataType parse_datatypes(String code);

    public boolean refact(DecomDiff diff);

    public void clear_comments(Address addr);

    public boolean add_comments(Address addr, List<Map.Entry<String, String>> comments);
}
