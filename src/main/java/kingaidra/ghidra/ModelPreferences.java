package kingaidra.ghidra;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.framework.preferences.Preferences;
import kingaidra.decom.ai.Model;
import kingaidra.decom.ai.ModelByScript;

public class ModelPreferences implements GhidraPreferences<Model> {
    private static final String PATH = BASE + "model.";

    private Map<String, Model> model_map;

    public ModelPreferences() {
        model_map = new HashMap<>();
    }

    private Model get_model(String path) {
        if (Preferences.getProperty(path, "").equals("ModelByScript")) {
            String model_name = Preferences.getProperty(path + ".name", "");
            String model_script_file = Preferences.getProperty(path + ".script_file", "");
            boolean model_active =
                    Boolean.parseBoolean(Preferences.getProperty(path + ".active", "false"));
            if (model_name.isEmpty() || model_script_file.isEmpty()) {
                return null;
            }
            return new ModelByScript(model_name, model_script_file, model_active);
        }
        return null;
    }

    public Model[] get_list() {
        return model_map.values().toArray(new Model[] {});
        /*
        List<Model> model_list = new ArrayList<>();
        for (String path : Preferences.getPropertyNames()) {
            if (!path.startsWith(PATH) || path.length() <= PATH.length()) {
                continue;
            }
            String key = path.substring(PATH.length());
            if (key.contains(".")) {
                continue;
            }

            Model m = get_model(path);
            if (m == null) {
                continue;
            }
            model_list.add(m);
        }
        return model_list.toArray(new Model[] {});
        */
    }

    public Model get(String key) {
        for (Model model : model_map.values()) {
            if (model.get_name().equals(key)) {
                return model;
            }
        }
        return null;
        // return get_model(PATH + key);
    }

    public void store(String key, Model data) {
        model_map.put(key, data);
        /*
        String class_name = data.getClass().getSimpleName();
        if (class_name.equals("ModelByScript")) {
            ModelByScript model = (ModelByScript) data;
            Preferences.setProperty(PATH + key, class_name);
            Preferences.setProperty(PATH + key + ".name", model.get_name());
            Preferences.setProperty(PATH + key + ".script_file", model.get_script());
            Preferences.setProperty(PATH + key + ".active", Boolean.toString(model.get_active()));
            Preferences.store();
        }
        */
    }

    public void remove(String key) {
        model_map.remove(key);
        /*
        Preferences.removeProperty(PATH + key);
        Preferences.removeProperty(PATH + key + ".name");
        Preferences.removeProperty(PATH + key + ".script_file");
        Preferences.removeProperty(PATH + key + ".active");
        Preferences.store();
        */
    }
}
