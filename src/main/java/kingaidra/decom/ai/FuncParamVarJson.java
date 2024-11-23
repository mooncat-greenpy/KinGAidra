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

public class FuncParamVarJson {
    public String new_func_name;
    public String orig_func_name;
    public List<ParamJson> parameters;
    public List<VarJson> variables;
}
