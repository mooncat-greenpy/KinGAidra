package kingaidra.keyfunc.extractor;

import kingaidra.decom.extractor.JsonExtractor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

public class QuoteExtractorTest {

    @Test
    void test() throws Exception {
        String s1 = "```json\n" +
                        "{\n" +
                        "    \"test\": [\n" +
                        "        \"test_1\",\n" +
                        "        \"test_2\",\n" +
                        "        \"test_3\"\n" +
                        "    ]\n" +
                        "}\n" +
                        "```" +
                        "- `string1`\n" +
                        "- `string2`, `string3`" +
                        "test\n" +
                        "```cpp\n" +
                        "test\n" +
                        "```";
        QuoteExtractor extractor = new QuoteExtractor(s1);
        List<String> data1 = extractor.get_strings();
        assertEquals(data1.size(), 3);
        assertEquals(data1.get(0), "string1");
        assertEquals(data1.get(1), "string2");
        assertEquals(data1.get(2), "string3");
    }
}
