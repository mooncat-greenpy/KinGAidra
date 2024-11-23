package kingaidra.testutil;

import java.util.HashMap;
import java.util.Map;

import kingaidra.chat.ai.Model;
import kingaidra.ghidra.GhidraPreferences;

public class ModelPreferencesDummy implements GhidraPreferences<Model> {
    private Map<String, Model> model_map;

    public ModelPreferencesDummy() {
        model_map = new HashMap<>();
    }

    public Model[] get_list() {
        return model_map.values().toArray(new Model[] {});
    }

    public Model get(String key) {
        for (Model model : model_map.values()) {
            if (model.get_name().equals(key)) {
                return model;
            }
        }
        return null;
    }

    public void store(String key, Model data) {
        model_map.put(key, data);
    }

    public void remove(String key) {
        model_map.remove(key);
    }

    public void remove_all() {
        model_map.clear();
    }
}
