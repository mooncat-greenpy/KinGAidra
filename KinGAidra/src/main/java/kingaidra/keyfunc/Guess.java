package kingaidra.keyfunc;

import java.util.AbstractMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelConf;
import kingaidra.ai.task.TaskType;
import kingaidra.decom.extractor.JsonExtractor;
import kingaidra.ghidra.PromptConf;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.keyfunc.extractor.FunctionReasonJson;
import kingaidra.keyfunc.extractor.StringListJson;

public class Guess {
    private static final String EXTRACT_PROMPT_MIDDLE =
            "\nOutput:\n" +
            "```text\n";
    private static final String EXTRACT_PROMPT_SUFFIX = "\n```";

    private GhidraUtil ghidra;
    private Ai ai;
    private ModelConf model_conf;
    private PromptConf conf;

    public Guess(GhidraUtil ghidra ,Ai ai, ModelConf model_conf, PromptConf conf) {
        this.ghidra = ghidra;
        this.ai = ai;

        this.model_conf = model_conf;
        this.conf = conf;
    }

    public ModelConf get_model_conf() {
        return model_conf;
    }

    private Model get_active_model() {
        for (String name : model_conf.get_models()) {
            Model tmp = model_conf.get_model(name);
            if (tmp != null && tmp.get_active()) {
                return tmp;
            }
        }
        return null;
    }

    private Conversation run_and_get_history(kingaidra.chat.Guess chat_guess, TaskType task, Address addr) {
        Conversation convo = chat_guess.guess(task, "", addr);
        if (convo == null) {
            return null;
        }
        return ai.get_history_convo(convo.get_uuid());
    }

    private Map.Entry<Function, String>[] extract_from_output(Model m, String source, String output, Address addr) {
        TaskType task = TaskType.KEYFUNC_FUNCTIONS;
        Conversation convo = new Conversation(ConversationType.SYSTEM_KEYFUNC, m);
        convo.add_system_msg(conf.get_system_prompt(task, m.get_name()));
        String prompt = conf.get_user_prompt(task, m.get_name()) + source + EXTRACT_PROMPT_MIDDLE + output + EXTRACT_PROMPT_SUFFIX;
        convo = ai.guess(task, convo, prompt, addr);
        if (convo == null) {
            return new Map.Entry[]{};
        }

        JsonExtractor<FunctionReasonJson> extractor =
                new JsonExtractor<>(convo.get_msg(convo.get_msgs_len() - 1), FunctionReasonJson.class);
        FunctionReasonJson func_reason_json = extractor.get_data();
        if (func_reason_json == null) {
            return new Map.Entry[]{};
        }

        List<Map.Entry<Function, String>> funcs = new LinkedList<>();
        for (FunctionReasonJson.FunctionReasonItem item : func_reason_json.get_funcs()) {
            List<Function> matched = ghidra.get_func(item.get_name());
            for (Function func : matched) {
                funcs.add(new AbstractMap.SimpleEntry<>(func, item.get_reason()));
            }
        }
        return funcs.toArray(new Map.Entry[]{});
    }

    private void merge_funcs(Map<Long, Map.Entry<Function, String>> merged, Map.Entry<Function, String>[] funcs) {
        for (Map.Entry<Function, String> item : funcs) {
            Function func = item.getKey();
            long key = func.getEntryPoint().getOffset();
            Map.Entry<Function, String> prev = merged.get(key);
            if (prev == null) {
                merged.put(key, item);
                continue;
            }
            merged.put(key, new AbstractMap.SimpleEntry<>(func, prev.getValue() + " / " + item.getValue()));
        }
    }

    private String[] extract_strings_by_ai(Model m, String source, String output, Address addr) {
        TaskType task = TaskType.KEYFUNC_STRINGS;
        Conversation convo = new Conversation(ConversationType.SYSTEM_KEYFUNC, m);
        convo.add_system_msg(conf.get_system_prompt(task, m.get_name()));
        String prompt = conf.get_user_prompt(task, m.get_name()) + source + EXTRACT_PROMPT_MIDDLE + output + EXTRACT_PROMPT_SUFFIX;
        convo = ai.guess(task, convo, prompt, addr);
        if (convo == null) {
            return new String[]{};
        }
        JsonExtractor<StringListJson> extractor =
                new JsonExtractor<>(convo.get_msg(convo.get_msgs_len() - 1), StringListJson.class);
        StringListJson string_json = extractor.get_data();
        if (string_json == null) {
            return new String[]{};
        }
        return string_json.get_strings().toArray(new String[]{});
    }

    private Map.Entry<Function, String>[] extract_from_strings_output(Model m, String source, String output, Address addr) {
        Data[] data_list = ghidra.get_strings();
        String[] strings = extract_strings_by_ai(m, source, output, addr);
        Map<Long, Map.Entry<Function, String>> funcs = new LinkedHashMap<>();
        for (String str : strings) {
            for (Data data : data_list) {
                if (!data.getDefaultValueRepresentation().contains(str)) {
                    continue;
                }
                List<Reference> refs = ghidra.get_ref_to(data.getAddress());
                if (refs == null) {
                    continue;
                }
                for (Reference ref : refs) {
                    Function func = ghidra.get_func(ref.getFromAddress());
                    if (func == null) {
                        continue;
                    }
                    long key = func.getEntryPoint().getOffset();
                    String reason = "`" + str + "`";
                    Map.Entry<Function, String> prev = funcs.get(key);
                    if (prev == null) {
                        funcs.put(key, new AbstractMap.SimpleEntry<>(func, reason));
                    } else if (!prev.getValue().contains("`" + str + "`")) {
                        funcs.put(key, new AbstractMap.SimpleEntry<>(func, prev.getValue() + ", `" + str + "`"));
                    }
                }
            }
        }
        return funcs.values().toArray(new Map.Entry[]{});
    }

    public Map.Entry<Function, String>[] guess_by_chat_histories(Address addr) {
        Model m = get_active_model();
        if (m == null) {
            return new Map.Entry[]{};
        }

        kingaidra.chat.Guess chat_guess = new kingaidra.chat.Guess(ai, model_conf, conf);
        Conversation malware_history = run_and_get_history(chat_guess, TaskType.CHAT_MALWARE_BEHAVIOR_OVERVIEW, addr);
        Conversation strings_history = run_and_get_history(chat_guess, TaskType.CHAT_EXPLAIN_STRINGS, addr);

        Map<Long, Map.Entry<Function, String>> merged = new LinkedHashMap<>();
        if (malware_history != null && malware_history.get_msgs_len() > 0) {
            String output = malware_history.get_msg(malware_history.get_msgs_len() - 1);
            merge_funcs(merged, extract_from_output(m, "Quick malware behavior overview with AI", output, addr));
        }
        if (strings_history != null && strings_history.get_msgs_len() > 0) {
            String output = strings_history.get_msg(strings_history.get_msgs_len() - 1);
            merge_funcs(merged, extract_from_strings_output(m, "Explain strings", output, addr));
        }
        return merged.values().toArray(new Map.Entry[]{});
    }
}
