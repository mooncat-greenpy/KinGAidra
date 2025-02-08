package kingaidra.decom.extractor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

public class JsonExtractor<T extends JsonDataInterface> {

    private T data;
    private final Class<T> type;

    public JsonExtractor(String s, Class<T> type) {
        this.type = type;
        data = extract_json(s);
        if (data != null) {
            return;
        }
        data = extract_json_md(s);
        if (data != null) {
            return;
        }
        data = extract_json_bf(s);
        if (data != null) {
            return;
        }
    }

    public T get_data() {
        return data;
    }

    private T extract_json_md(String s) {
        String pre = "```json";
        String post = "```";
        int start = s.indexOf(pre);
        if (start < 0) {
            start = 0;
        } else {
            start += pre.length();
        }
        int end = s.indexOf(post, start);
        if (end < 0) {
            end = s.length();
        }
        String target = s.substring(start, end);
        return extract_json(target);
    }

    private T extract_json_bf(String s) {
        if (!s.contains("{") || !s.contains("}")) {
            return null;
        }

        int length = s.length();
        for (int pre = 0; pre < length; pre++) {
            for (int post = length; post > 0; post--) {
                if (post <= pre) {
                    break;
                }
                String target = s.substring(pre, post);
                if (!target.contains("{") || !target.contains("}")) {
                    break;
                }
                if ((!target.startsWith("{") || !target.endsWith("}")) &&
                    (!target.startsWith("[") || !target.endsWith("]"))) {
                    continue;
                }

                T j = extract_json(target);
                if (j != null) {
                    return j;
                }
            }
        }
        return null;
    }

    private T extract_json(String s) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            T data = objectMapper.readValue(s, type);
            if (data == null || !data.validate()) {
                return null;
            }
            return data;
        } catch (JsonProcessingException e) {
            return null;
        }
    }
}
