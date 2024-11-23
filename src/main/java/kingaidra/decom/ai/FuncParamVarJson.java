package kingaidra.decom.ai;

import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;

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
