package kingaidra.ghidra;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.framework.preferences.Preferences;
import kingaidra.chat.ai.Model;
import kingaidra.chat.ai.ModelByScript;
import kingaidra.decom.ai.ModelType;

public class ChatModelPreferences implements GhidraPreferences<Model> {

    private static final String PATH = BASE + "chat.model.";
    private static final String VERSION = "0.0.1";

    public ChatModelPreferences() {
        Preferences.setProperty(PATH.substring(0, PATH.length() - 1), VERSION);
    }

    private Model get_model(String path) {
        if (Preferences.getProperty(path, "").equals("ModelByScript")) {
            String model_name = Preferences.getProperty(path + ".name", "");
            String model_script_file = Preferences.getProperty(path + ".script_file", "");
            boolean model_active =
                    Boolean.parseBoolean(Preferences.getProperty(path + ".active", "false"));
            ModelType model_type =
                    ModelType.valueOf(Preferences.getProperty(path + ".type", "DECOM_REFACTOR"));
            if (model_type != ModelType.CHAT) {
                return null;
            }
            if (model_name.isEmpty() || model_script_file.isEmpty()) {
                return null;
            }
            Model m = new ModelByScript(model_name, model_script_file, model_active);
            m.set_type(model_type);
            return m;
        }
        return null;
    }

    public Model[] get_list() {
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
    }

    public Model get(String key) {
        return get_model(PATH + key);
    }

    public void store(String key, Model data) {
        String class_name = data.getClass().getSimpleName();
        if (class_name.equals("ModelByScript")) {
            ModelByScript model = (ModelByScript) data;
            Preferences.setProperty(PATH + key, class_name);
            Preferences.setProperty(PATH + key + ".name", model.get_name());
            Preferences.setProperty(PATH + key + ".script_file", model.get_script());
            Preferences.setProperty(PATH + key + ".active", Boolean.toString(model.get_active()));
            Preferences.setProperty(PATH + key + ".type", model.get_type().toString());
            Preferences.store();
        }
    }

    public void remove(String key) {
        Preferences.removeProperty(PATH + key);
        Preferences.removeProperty(PATH + key + ".name");
        Preferences.removeProperty(PATH + key + ".script_file");
        Preferences.removeProperty(PATH + key + ".active");
        Preferences.removeProperty(PATH + key + ".type");
        Preferences.store();
    }

    public void remove_all() {
        for (String path : Preferences.getPropertyNames()) {
            if (!path.startsWith(PATH)) {
                continue;
            }
            Preferences.removeProperty(path);
        }
    }
}
