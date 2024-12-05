package kingaidra.decom;

import java.util.LinkedList;
import java.util.List;

import ghidra.program.model.data.DataType;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.model.Model;
import kingaidra.ai.task.TaskType;
import kingaidra.decom.extractor.ClangExtractor;
import kingaidra.ghidra.GhidraUtil;

public class Refactor {
    private GhidraUtil ghidra;
    private Ai ai;

    public Refactor(GhidraUtil ghidra, Ai ai) {
        this.ghidra = ghidra;
        this.ai = ai;
    }

    public DataType resolve_datatype(String datatype_name, Model model) {
        Conversation convo = new Conversation(model);
        datatype_name = datatype_name.replaceAll("\\[\\d:\\]", "");
        String msg = String.format("Please write the %s structure in C language. " +
                        "Include any dependent data types and structures. " +
                        "Do not use #include or #define. " +
                        "It is for %d-bit. ", datatype_name, ghidra.get_addr(0).getSize());

        convo = ai.guess(TaskType.RESOLVE_DATATYPE, convo, msg, null);
        if (convo == null) {
            return null;
        }

        String rsp_msg = convo.get_msg(convo.get_msgs_len() - 1);
        ClangExtractor extractor = new ClangExtractor(rsp_msg);
        String target = extractor.get_data();
        if (target == null) {
            return null;
        }

        DataType dt = ghidra.parse_datatypes(target);
        return dt;
    }

    public void refact(DecomDiff diff, boolean datatype_resolving) {
        if (datatype_resolving) {
            for (DiffPair pair : diff.get_datatypes()) {
                List<DataType> dt_list = new LinkedList<>();
                ghidra.find_datatypes(pair.get_new_name(), dt_list);
                if (dt_list.size() > 0) {
                    continue;
                }
                DataType dt = resolve_datatype(pair.get_new_name(), diff.get_model());
                if (dt == null) {
                    continue;
                }
                ghidra.add_datatype(dt);
            }
        }

        ghidra.refact(diff);
    }
}
