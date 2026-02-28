package kingaidra.keyfunc.extractor;

import java.util.List;

import kingaidra.decom.extractor.JsonDataInterface;

public class StringListJson implements JsonDataInterface {
    public List<String> str;

    public List<String> get_strings() {
        return str;
    }

    @Override
    public boolean validate() {
        if (str == null) {
            return false;
        }
        for (String s : str) {
            if (s == null) {
                return false;
            }
        }
        return true;
    }
}
