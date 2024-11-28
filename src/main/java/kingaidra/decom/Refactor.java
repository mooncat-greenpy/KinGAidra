package kingaidra.decom;

import java.util.LinkedList;
import java.util.List;

import ghidra.program.model.data.DataType;
import kingaidra.decom.ai.Ai;
import kingaidra.ghidra.GhidraUtil;

public class Refactor {
    private GhidraUtil ghidra;
    private Ai ai;

    public Refactor(GhidraUtil ghidra, Ai ai) {
        this.ghidra = ghidra;
        this.ai = ai;
    }

    public void refact(DecomDiff diff, boolean datatype_resolving) {
        if (datatype_resolving) {
            for (DiffPair pair : diff.get_datatypes()) {
                List<DataType> dt_list = new LinkedList<>();
                ghidra.find_datatypes(pair.get_new_name(), dt_list);
                if (dt_list.size() > 0) {
                    continue;
                }
                DataType dt = ai.guess(pair.get_new_name(), diff.get_model());
                if (dt == null) {
                    continue;
                }
                ghidra.add_datatype(dt);
            }
        }

        ghidra.refact(diff);
    }
}
