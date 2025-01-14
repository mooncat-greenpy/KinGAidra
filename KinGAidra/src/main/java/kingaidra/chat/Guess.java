package kingaidra.chat;

import java.util.Arrays;

import ghidra.program.model.address.Address;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelByScript;
import kingaidra.ai.task.TaskType;
import kingaidra.ghidra.GhidraPreferences;

public class Guess {
    private Ai ai;
    private GhidraPreferences<Model> pref;

    public Guess(Ai ai, GhidraPreferences<Model> pref) {
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

    public Conversation guess(Conversation convo, String msg, Address addr) {
        convo = ai.guess(TaskType.CHAT, convo, msg, addr);
        return convo;
    }

    public Conversation guess(String msg, Address addr) {
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
        Conversation convo = new Conversation(ConversationType.USER, m);
        convo.set_model(m);
        return guess(convo, msg, addr);
    }
}
