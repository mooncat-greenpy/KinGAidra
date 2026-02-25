package kingaidra.decom.extractor;

import java.util.List;

public class DecompileViewRefactorJson implements JsonDataInterface {
    public String new_func_name;
    public String orig_func_name;
    public List<ParamJson> parameters;
    public List<VarJson> variables;
    public List<DataTypeJson> datatypes;

    public String get_new_func_name() {
        return new_func_name;
    }

    public String get_orig_func_name() {
        return orig_func_name;
    }

    public List<ParamJson> get_parameters() {
        return parameters;
    }

    public List<VarJson> get_variables() {
        return variables;
    }

    public List<DataTypeJson> get_datatypes() {
        return datatypes;
    }

    @Override
    public boolean validate() {
        return new_func_name != null
                && orig_func_name != null
                && parameters != null
                && variables != null
                && datatypes != null;
    }
}
