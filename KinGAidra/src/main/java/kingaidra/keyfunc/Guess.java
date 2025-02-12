package kingaidra.keyfunc;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelByScript;
import kingaidra.ai.model.ModelConf;
import kingaidra.ai.task.TaskType;
import kingaidra.decom.extractor.JsonExtractor;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.keyfunc.extractor.FunctionJson;
import kingaidra.keyfunc.extractor.MarkupExtractor;

public class Guess {
    private GhidraUtil ghidra;
    private Ai ai;
    private ModelConf model_conf;

    public Guess(GhidraUtil ghidra ,Ai ai, ModelConf conf) {
        this.ghidra = ghidra;
        this.ai = ai;

        model_conf = conf;
    }

    public ModelConf get_model_conf() {
        return model_conf;
    }

    public Conversation guess_by_strings(Conversation convo) {
        String msg = "Given a list of strings found within a malware sample, identify and list the strings that might be useful for further analysis. Focus on strings that could provide insight into the malware's functionality, its command-and-control server, or its intentions. Prioritize strings related to:\n" +
                                                "\n" +
                                                "1. URLs or IP addresses - Potential command-and-control servers, communication endpoints, or external resources.\n" +
                                                "2. File paths or registry keys - Locations of potential artifacts, dropped files, or persistence mechanisms.\n" +
                                                "3. Function names or API calls - Indications of specific malware behaviors or techniques.\n" +
                                                "4. Encryption keys or sensitive data - Possible use of cryptography, encoding, or sensitive information handling.\n" +
                                                "5. Error messages or logs - Clues to how the malware operates, crashes, or logs activity.\n" +
                                                "6. Hardcoded credentials or authentication tokens - Useful for identifying compromised access methods.\n" +
                                                "7. Strings associated with known malware families or threat actor tactics - Help in associating the sample with a specific threat group or malware variant.\n" +
                                                "\n" +
                                                "Filter out irrelevant or common strings such as system files, non-specific text, or internal programming strings. Focus on identifying strings that could reveal malicious actions or associations.\n" +
                                                "\n" +
                                                "Strings:\n" +
                                                "<strings>";
        convo = ai.guess(TaskType.KEYFUNC_STRING, convo, msg, null);
        return convo;
    }

    public String[] guess_by_strings() {
        Model m = null;
        for (String name : model_conf.get_models()) {
            Model tmp = model_conf.get_model(name);
            if (tmp.get_active()) {
                m = tmp;
                break;
            }
        }
        if (m == null) {
            return new String[]{};
        }
        Conversation convo = new Conversation(ConversationType.SYSTEM_KEYFUNC, m);
        convo.set_model(m);
        convo = guess_by_strings(convo);
        if (convo == null) {
            return new String[]{};
        }

        MarkupExtractor extractor = new MarkupExtractor(convo.get_msg(convo.get_msgs_len() - 1));
        List<String> strings = extractor.get_strings();
        if (strings == null) {
            return new String[]{};
        }
        return strings.toArray(new String[]{});
    }

    public Data[] guess_string_data() {
        String[] strings = guess_by_strings();
        List<Data> ret = new LinkedList<>();
        Data[] str_data = ghidra.get_strings();
        for (String str : strings) {
            for (Data d : str_data) {
                if (!d.getDefaultValueRepresentation().contains(str) || ret.contains(d)) {
                    continue;
                }
                ret.add(d);
            }
        }
        return ret.toArray(new Data[]{});
    }

    public Conversation guess(Conversation convo, String call_tree, Address addr) {
        String pre_msg = "Step 1: Since the message is long, I will send it in many parts.\n" +
                        "Step 2: Once you have sent all of it, tell me \"Done.\"\n" +
                        "Step 3: Please just reply \"Understood\" until I say \"Done.\"\n" +
                        "Below is the function call tree for this program.\n" +
                        "Once I say \"Done,\" please answer the questions.\n";
        int max_line = 50;
        int num_line = 0;
        String one_msg = "";
        for (String line : (pre_msg + call_tree).split("\n")) {
            num_line++;
            one_msg += line + "\n";
            if (num_line >= max_line) {
                convo.add_user_msg(one_msg);
                convo.add_assistant_msg("Understood");
                num_line = 0;
                one_msg = "";
            }
        }
        convo.add_user_msg(one_msg);
        convo.add_assistant_msg("Understood");

        String ask_msg = "Done, please list which functions would be good to analyze first to get the big picture of this program.\n" +
                        "Output format.\n" +
                        "```json\n" +
                        "{\n" +
                        "    \"func\": [\n" +
                        "        \"Function1\",\n" +
                        "        \"Function2\",\n" +
                        "        \"Function3\",\n" +
                        "        ...\n" +
                        "    ]\n" +
                        "}\n" +
                        "```";
        convo = ai.guess(TaskType.KEYFUNC_CALLTREE, convo, ask_msg, addr);
        return convo;
    }

    public Function[] guess(String call_tree, Address addr) {
        Model m = null;
        for (String name : model_conf.get_models()) {
            Model tmp = model_conf.get_model(name);
            if (tmp.get_active()) {
                m = tmp;
                break;
            }
        }
        if (m == null) {
            return null;
        }
        Conversation convo = new Conversation(ConversationType.SYSTEM_KEYFUNC, m);
        convo.set_model(m);
        convo = guess(convo, call_tree, addr);
        if (convo == null) {
            return null;
        }

        JsonExtractor<FunctionJson> extractor = new JsonExtractor<>(convo.get_msg(convo.get_msgs_len() - 1), FunctionJson.class);
        FunctionJson func_json = extractor.get_data();
        if (func_json == null) {
            return null;
        }
        List<Function> funcs = new LinkedList<>();
        for (String name : func_json.get_funcs()) {
            funcs.addAll(ghidra.get_func(name));
        }
        return funcs.toArray(new Function[]{});
    }
}
