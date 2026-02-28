package kingaidra.keyfunc.extractor;

import org.junit.jupiter.api.Test;

import kingaidra.decom.extractor.JsonExtractor;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class StringListJsonTest {

    @Test
    void test() throws Exception {
        String s1 = "```json\n" +
                        "{\n" +
                        "    \"str\": [\n" +
                        "        \"string1\",\n" +
                        "        \"string2\"\n" +
                        "    ]\n" +
                        "}\n" +
                        "```";
        JsonExtractor<StringListJson> extractor = new JsonExtractor<>(s1, StringListJson.class);
        StringListJson data = extractor.get_data();
        assertEquals(data.get_strings().size(), 2);
        assertEquals(data.get_strings().get(0), "string1");
        assertEquals(data.get_strings().get(1), "string2");
    }
}
