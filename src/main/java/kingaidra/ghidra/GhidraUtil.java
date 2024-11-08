package kingaidra.ghidra;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import kingaidra.decom.DecomDiff;

public interface GhidraUtil {
    public Address get_current_addr();

    public Function get_func(Address addr);

    public String get_decom(Address addr);

    public DecomDiff get_decomdiff(Address addr);

    public boolean refact(DecomDiff diff);
}
