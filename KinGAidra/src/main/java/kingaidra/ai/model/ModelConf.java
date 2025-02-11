package kingaidra.ai.model;

import kingaidra.ai.model.Model;

public interface ModelConf {
    public Model get_model(String name);

    public String[] get_models();

    public int get_models_len();

    public boolean exist_model(String name);

    public String get_model_script(String name);

    public boolean get_model_status(String name);

    public void set_model_name(String name, String new_name);

    public void set_model_script(String name, String script_file);

    public void set_model_status(String name, boolean status);

    public void add_model(String name, String script_file);

    public void remove_model(String name);
}
