package kingaidra.decom.extractor;

import java.util.ArrayList;

public class CommentListJson extends ArrayList<CommentJson> implements JsonDataInterface {

    @Override
    public boolean validate() {
        return true;
    }
}
