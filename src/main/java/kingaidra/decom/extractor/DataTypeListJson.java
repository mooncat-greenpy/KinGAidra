package kingaidra.decom.extractor;

import java.util.ArrayList;

public class DataTypeListJson extends ArrayList<DataTypeJson> implements JsonDataInterface {

    @Override
    public boolean validate() {
        return true;
    }
}
