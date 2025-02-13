package kingaidra.ai.model;

public interface ModelConf {
    public String get_name();

    public Model get_model(String model_name);

    public String[] get_models();

    public int get_models_len();

    public boolean exist_model(String model_name);

    public String get_model_script(String model_name);

    public boolean get_model_status(String model_name);

    public void set_model_name(String model_name, String new_model_name);

    public void set_model_script(String model_name, String script_file);

    public void set_model_status(String model_name, boolean status);

    public void add_model(String model_name, String script_file);

    public void remove_model(String model_name);
}
