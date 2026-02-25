package kingaidra.ghidra;

import ghidra.program.model.data.DataType;

public class DataTypeParseResult {
    private final DataType datatype;
    private final String error_reason;

    public DataTypeParseResult(DataType datatype, String error_reason) {
        this.datatype = datatype;
        this.error_reason = error_reason;
    }

    public DataType get_datatype() {
        return datatype;
    }

    public String get_error_reason() {
        return error_reason;
    }

    public boolean is_success() {
        return datatype != null;
    }
}
