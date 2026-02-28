package kingaidra.keyfunc.extractor;

import java.util.List;

import kingaidra.decom.extractor.JsonDataInterface;

public class FunctionReasonJson implements JsonDataInterface {
    public List<FunctionReasonItem> func;

    public List<FunctionReasonItem> get_funcs() {
        return func;
    }

    @Override
    public boolean validate() {
        if (func == null) {
            return false;
        }
        for (FunctionReasonItem item : func) {
            if (item == null || !item.validate()) {
                return false;
            }
        }
        return true;
    }

    public static class FunctionReasonItem {
        public String name;
        public String reason;

        public String get_name() {
            return name;
        }

        public String get_reason() {
            return reason;
        }

        public boolean validate() {
            return name != null && reason != null;
        }
    }
}
