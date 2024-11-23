package kingaidra.decom.ai;

import java.util.List;

class ParamJson {
    public String new_param_name;
    public String orig_param_name;
}

class VarJson {
    public String new_var_name;
    public String orig_var_name;
}

public class FuncParamVarJson implements JsonDataInterface {
    public String new_func_name;
    public String orig_func_name;
    public List<ParamJson> parameters;
    public List<VarJson> variables;

    @Override
    public boolean validate() {
        return new_func_name != null && orig_func_name != null && parameters != null && variables != null;
    }
}
