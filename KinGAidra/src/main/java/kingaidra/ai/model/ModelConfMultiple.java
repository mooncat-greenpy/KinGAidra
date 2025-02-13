package kingaidra.ai.model;

import java.util.Arrays;

import kingaidra.ghidra.GhidraPreferences;

public class ModelConfMultiple implements ModelConf {
    private String name;
    private GhidraPreferences<Model> pref;

    public ModelConfMultiple(String name, GhidraPreferences<Model> pref) {
        this.name = name;
        this.pref = pref;
    }

    public String get_name() {
        return name;
    }

    public Model get_model(String model_name) {
        for (Model model : pref.get_list()) {
            if (model.get_name().equals(model_name)) {
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

    public boolean exist_model(String model_name) {
        return Arrays.stream(pref.get_list()).anyMatch(p -> p.get_name().equals(model_name));
    }

    public String get_model_script(String model_name) {
        Model m = get_model(model_name);
        if (m == null) {
            return null;
        }
        return m.get_script();
    }

    public boolean get_model_status(String model_name) {
        Model m = get_model(model_name);
        if (m == null) {
            return false;
        }
        return m.get_active();
    }

    public void set_model_name(String model_name, String new_model_name) {
        Model m = get_model(model_name);
        if (m == null) {
            return;
        }
        m.set_name(new_model_name);
    }

    public void set_model_script(String model_name, String script_file) {
        Model m = get_model(model_name);
        if (m == null) {
            return;
        }
        m.set_script(script_file);
        pref.store(model_name, m);
    }

    public void set_model_status(String model_name, boolean status) {
        Model m = get_model(model_name);
        if (m == null) {
            return;
        }
        m.set_active(status);
        pref.store(model_name, m);
    }

    public void add_model(String model_name, String script_file) {
        Model m = new ModelByScript(model_name, script_file, false);
        pref.store(model_name, m);
    }

    public void remove_model(String model_name) {
        Model m = get_model(model_name);
        if (m == null) {
            return;
        }
        pref.remove(model_name);
    }
}
