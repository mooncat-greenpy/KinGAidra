package kingaidra.ghidra;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import kingaidra.decom.DecomDiff;

public interface GhidraUtil {
    public Address get_current_addr();

    public Address get_addr(long addr_value);

    public Function get_func(Address addr);

    public List<Function> get_func(String name);

    public void get_root_func(List<Function> root);

    public String get_func_call_tree();

    public String get_func_call_tree(Function func);

    public String get_asm(Address addr);

    public String get_decom(Address addr);

    public DecomDiff get_decomdiff(Address addr);

    public void find_datatypes(String name, List<DataType> dt_list);

    public void add_datatype(DataType dt);

    public DataType parse_datatypes(String code);

    public boolean refact(DecomDiff diff);
}
