package kingaidra.keyfunc;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelByScript;
import kingaidra.ai.task.TaskType;
import kingaidra.decom.extractor.JsonExtractor;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.keyfunc.extractor.FunctionJson;

public class Guess {
    private GhidraUtil ghidra;
    private Ai ai;
    private GhidraPreferences<Model> pref;

    public Guess(GhidraUtil ghidra ,Ai ai, GhidraPreferences<Model> pref) {
        this.ghidra = ghidra;
        this.ai = ai;
        this.pref = pref;

        boolean exist_true = false;
        for (String n : get_models()) {
            boolean status = get_model_status(n);
            if (status) {
                exist_true = true;
            }
            set_model_status(n, status);
            pref.store(n, get_model(n));
        }

        if (get_models_len() > 0 && !exist_true) {
            set_model_status(get_models()[0], true);
        }
    }

    private Model get_model(String name) {
        for (Model model : pref.get_list()) {
            if (model.get_name().equals(name)) {
                return model;
            }
        }
        return null;
    }

    public String[] get_models() {
        return Arrays.stream(pref.get_list()).map(Model::get_name).toArray(String[]::new);
    }

    public int get_models_len() {
        return pref.get_list().length;
    }

    public boolean exist_model(String name) {
        return Arrays.stream(pref.get_list()).anyMatch(p -> p.get_name().equals(name));
    }

    public String get_model_script(String name) {
        Model m = get_model(name);
        if (m == null) {
            return null;
        }
        return m.get_script();
    }

    public boolean get_model_status(String name) {
        Model m = get_model(name);
        if (m == null) {
            return false;
        }
        return m.get_active();
    }

    public void set_model_name(String name, String new_name) {
        Model m = get_model(name);
        if (m == null) {
            return;
        }
        m.set_name(new_name);
    }

    public void set_model_script(String name, String script_file) {
        Model m = get_model(name);
        if (m == null) {
            return;
        }
        m.set_script(script_file);
        pref.store(name, m);
    }

    public void set_model_status(String name, boolean status) {
        if (!status) {
            return;
        }
        Model m = get_model(name);
        if (m == null) {
            return;
        }

        for (String i_n : get_models()) {
            Model i_m = get_model(i_n);
            i_m.set_active(false);
            pref.store(i_m.get_name(), i_m);
        }
        m.set_active(status);
        pref.store(name, m);
    }

    public void add_model(String name, String script_file) {
        Model m = new ModelByScript(name, script_file, true);
        pref.store(name, m);

        set_model_status(name, true);
    }

    public void remove_model(String name) {
        Model m = get_model(name);
        if (m == null) {
            return;
        }
        pref.remove(name);
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
        convo = ai.guess(TaskType.KEY_FUNC, convo, ask_msg, addr);
        return convo;
    }

    public Function[] guess(String call_tree, Address addr) {
        Model m = null;
        for (String name : get_models()) {
            Model tmp = get_model(name);
            if (tmp.get_active()) {
                m = tmp;
                break;
            }
        }
        if (m == null) {
            return null;
        }
        Conversation convo = new Conversation(m);
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