package kingaidra.keyfunc.extractor;

import java.util.List;

import kingaidra.decom.extractor.JsonDataInterface;

public class FunctionJson implements JsonDataInterface {
    public List<String> func;

    public List<String> get_funcs() {
        return func;
    }

    @Override
    public boolean validate() {
        return func != null;
    }
}
