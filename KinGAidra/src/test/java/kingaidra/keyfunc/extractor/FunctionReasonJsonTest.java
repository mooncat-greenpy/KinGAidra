package kingaidra.keyfunc.extractor;

import org.junit.jupiter.api.Test;

import kingaidra.decom.extractor.JsonExtractor;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class FunctionReasonJsonTest {

    @Test
    void test() throws Exception {
        String s1 = "```json\n" +
                        "{\n" +
                        "    \"func\": [\n" +
                        "        {\n" +
                        "            \"name\": \"Func_1\",\n" +
                        "            \"reason\": \"reason1\"\n" +
                        "        },\n" +
                        "        {\n" +
                        "            \"name\": \"Func_2\",\n" +
                        "            \"reason\": \"reason2\"\n" +
                        "        }\n" +
                        "    ]\n" +
                        "}\n" +
                        "```";
        JsonExtractor<FunctionReasonJson> extractor = new JsonExtractor<>(s1, FunctionReasonJson.class);
        FunctionReasonJson data = extractor.get_data();
        assertEquals(data.get_funcs().size(), 2);
        assertEquals(data.get_funcs().get(0).get_name(), "Func_1");
        assertEquals(data.get_funcs().get(0).get_reason(), "reason1");
        assertEquals(data.get_funcs().get(1).get_name(), "Func_2");
        assertEquals(data.get_funcs().get(1).get_reason(), "reason2");
    }
}
