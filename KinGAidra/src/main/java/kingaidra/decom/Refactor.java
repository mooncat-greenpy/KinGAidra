package kingaidra.decom;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import ghidra.program.model.data.DataType;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.task.TaskType;
import kingaidra.decom.extractor.ClangExtractor;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.PromptConf;

public class Refactor {
    private GhidraUtil ghidra;
    private Ai ai;
    private PromptConf conf;
    private Function<String, String> fix_func;

    public Refactor(GhidraUtil ghidra, Ai ai, PromptConf conf, Function<String, String> fix_func) {
        this.ghidra = ghidra;
        this.ai = ai;
        this.conf = conf;
        this.fix_func = fix_func;
    }

    public DataType resolve_datatype(String datatype_name, Model model) {
        TaskType task = TaskType.DECOM_RESOLVE_DATATYPE;
        Conversation convo = new Conversation(ConversationType.SYSTEM_DECOM, model);
        convo.add_system_msg(conf.get_system_prompt(task, model.get_name()));

        String msg_template = conf.get_user_prompt(task, model.get_name());
        String msg = msg_template
                .replace("<datatype_name>", datatype_name)
                .replace("<bit_size>", String.format("%d", ghidra.get_addr(0).getSize()));

        convo = ai.guess(task, convo, msg, null);
        if (convo == null) {
            return null;
        }
        String rsp_msg = convo.get_msg(convo.get_msgs_len() - 1);

        // TODO: Refact
        rsp_msg = fix_func.apply(rsp_msg);
        if (rsp_msg == null) {
            return null;
        }

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
            Set<String> datatype_names = new HashSet<>();
            for (DiffPair pair : diff.get_datatypes()) {
                datatype_names.add(pair.get_new_name());
            }

            for (String datatype_name : datatype_names) {
                List<DataType> dt_list = new LinkedList<>();
                ghidra.find_datatypes(datatype_name, dt_list);
                if (dt_list.size() > 0) {
                    continue;
                }
                String name = datatype_name.replaceAll("\\[\\d+\\]", "");
                dt_list = new LinkedList<>();
                ghidra.find_datatypes(name, dt_list);
                if (dt_list.size() > 0) {
                    continue;
                }
                DataType dt = resolve_datatype(name, diff.get_model());
                if (dt == null) {
                    continue;
                }
                ghidra.add_datatype(dt);
            }
        }

        ghidra.refact(diff);
    }
}
