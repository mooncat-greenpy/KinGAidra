package kingaidra.keyfunc.extractor;

import com.fasterxml.jackson.databind.ObjectMapper;

import kingaidra.decom.extractor.JsonExtractor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class FunctionJsonTest {

    @Test
    void test() throws Exception {
        String s1 = "```json\n" +
                        "{\n" +
                        "    \"func\": [\n" +
                        "        \"Func_1\",\n" +
                        "        \"Func_2\",\n" +
                        "        \"Func_3\"\n" +
                        "    ]\n" +
                        "}\n" +
                        "```";
        JsonExtractor<FunctionJson> extractor = new JsonExtractor(s1, FunctionJson.class);
        FunctionJson data1 = extractor.get_data();
        assertEquals(data1.get_funcs().size(), 3);
        assertEquals(data1.get_funcs().get(0), "Func_1");
        assertEquals(data1.get_funcs().get(1), "Func_2");
        assertEquals(data1.get_funcs().get(2), "Func_3");
    }
}
