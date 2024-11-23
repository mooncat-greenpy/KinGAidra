package kingaidra.decom.ai;

import java.util.ArrayList;

class DataTypeJson {
    public String new_datatype;
    public String orig_datatype;
    public String var_name;

    public String get_new_datatype() {
        return new_datatype;
    }

    public String get_orig_datatype() {
        return orig_datatype;
    }

    public String get_var_name() {
        return var_name;
    }
}

public class DataTypeListJson extends ArrayList<DataTypeJson> implements JsonDataInterface {

    @Override
    public boolean validate() {
        return true;
    }
}
