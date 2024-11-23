package kingaidra.decom.ai;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JsonExtractorTest {


    @Test
    void test() throws Exception {
        String s1 = "{\n" +
                   "    \"new_func_name\": \"new function name\",\n" +
                   "    \"orig_func_name\": \"original function name\",\n" +
                   "    \"parameters\": [\n" +
                   "        {\n" +
                   "            \"new_param_name\": \"new parameter name\",\n" +
                   "            \"orig_param_name\": \"original parameter name\"\n" +
                   "        }\n" +
                   "    ],\n" +
                   "    \"variables\": [\n" +
                   "        {\n" +
                   "            \"new_var_name\": \"new variable name\",\n" +
                   "            \"orig_var_name\": \"original variable name\"\n" +
                   "        }\n" +
                   "    ]\n" +
                   "}";
        JsonExtractor extractor = new JsonExtractor(s1);
        FuncParamVarJson data1 = extractor.get_data();
        assertEquals(data1.new_func_name, "new function name");
        assertEquals(data1.orig_func_name, "original function name");
        assertEquals(data1.parameters.size(), 1);
        assertEquals(data1.variables.size(), 1);
        assertEquals(data1.parameters.get(0).new_param_name, "new parameter name");
        assertEquals(data1.parameters.get(0).orig_param_name, "original parameter name");
        assertEquals(data1.variables.get(0).new_var_name, "new variable name");
        assertEquals(data1.variables.get(0).orig_var_name, "original variable name");

        String s2 = "{\n" +
                   "    \"new_func_name\": \"new function name\",\n" +
                   "    \"orig_func_name\": \"original function name\",\n" +
                   "    \"parameters\": [\n" +
                   "        {\n" +
                   "            \"new_param_name\": \"new parameter name\",\n" +
                   "            \"orig_param_name\": \"original parameter name\"\n" +
                   "        },\n" +
                   "        {\n" +
                   "            \"new_param_name\": \"new parameter name2\",\n" +
                   "            \"orig_param_name\": \"original parameter name2\"\n" +
                   "        }\n" +
                   "    ],\n" +
                   "    \"variables\": [\n" +
                   "        {\n" +
                   "            \"new_var_name\": \"new variable name\",\n" +
                   "            \"orig_var_name\": \"original variable name\"\n" +
                   "        },\n" +
                   "        {\n" +
                   "            \"new_var_name\": \"new variable name2\",\n" +
                   "            \"orig_var_name\": \"original variable name2\"\n" +
                   "        }\n" +
                   "    ]\n" +
                   "}";
        JsonExtractor extractor2 = new JsonExtractor(s2);
        FuncParamVarJson data2 = extractor2.get_data();
        assertEquals(data2.new_func_name, "new function name");
        assertEquals(data2.orig_func_name, "original function name");
        assertEquals(data2.parameters.size(), 2);
        assertEquals(data2.parameters.get(0).new_param_name, "new parameter name");
        assertEquals(data2.parameters.get(0).orig_param_name, "original parameter name");
        assertEquals(data2.parameters.get(1).new_param_name, "new parameter name2");
        assertEquals(data2.parameters.get(1).orig_param_name, "original parameter name2");
        assertEquals(data2.variables.size(), 2);
        assertEquals(data2.variables.get(0).new_var_name, "new variable name");
        assertEquals(data2.variables.get(0).orig_var_name, "original variable name");
        assertEquals(data2.variables.get(1).new_var_name, "new variable name2");
        assertEquals(data2.variables.get(1).orig_var_name, "original variable name2");
    }

    @Test
    void test_md() throws Exception {
        String s1 = "```json\n" +
                   "{\n" +
                   "    \"new_func_name\": \"new function name\",\n" +
                   "    \"orig_func_name\": \"original function name\",\n" +
                   "    \"parameters\": [\n" +
                   "        {\n" +
                   "            \"new_param_name\": \"new parameter name\",\n" +
                   "            \"orig_param_name\": \"original parameter name\"\n" +
                   "        }\n" +
                   "    ],\n" +
                   "    \"variables\": [\n" +
                   "        {\n" +
                   "            \"new_var_name\": \"new variable name\",\n" +
                   "            \"orig_var_name\": \"original variable name\"\n" +
                   "        }\n" +
                   "    ]\n" +
                   "}\n" +
                   "```";
        JsonExtractor extractor = new JsonExtractor(s1);
        FuncParamVarJson data1 = extractor.get_data();
        assertEquals(data1.new_func_name, "new function name");
        assertEquals(data1.orig_func_name, "original function name");
        assertEquals(data1.parameters.size(), 1);
        assertEquals(data1.variables.size(), 1);
        assertEquals(data1.parameters.get(0).new_param_name, "new parameter name");
        assertEquals(data1.parameters.get(0).orig_param_name, "original parameter name");
        assertEquals(data1.variables.get(0).new_var_name, "new variable name");
        assertEquals(data1.variables.get(0).orig_var_name, "original variable name");

        String s2 = "This is markdown. ```cpp\nint main() {}\n```\n" +
                   "```json\n" +
                   "{\n" +
                   "    \"new_func_name\": \"new function name\",\n" +
                   "    \"orig_func_name\": \"original function name\",\n" +
                   "    \"parameters\": [\n" +
                   "        {\n" +
                   "            \"new_param_name\": \"new parameter name\",\n" +
                   "            \"orig_param_name\": \"original parameter name\"\n" +
                   "        },\n" +
                   "        {\n" +
                   "            \"new_param_name\": \"new parameter name2\",\n" +
                   "            \"orig_param_name\": \"original parameter name2\"\n" +
                   "        }\n" +
                   "    ],\n" +
                   "    \"variables\": [\n" +
                   "        {\n" +
                   "            \"new_var_name\": \"new variable name\",\n" +
                   "            \"orig_var_name\": \"original variable name\"\n" +
                   "        },\n" +
                   "        {\n" +
                   "            \"new_var_name\": \"new variable name2\",\n" +
                   "            \"orig_var_name\": \"original variable name2\"\n" +
                   "        }\n" +
                   "    ]\n" +
                   "}\n" +
                   "```\n" +
                   "This is markdown. ```cpp\nint main() {}\n```\n";
        JsonExtractor extractor2 = new JsonExtractor(s2);
        FuncParamVarJson data2 = extractor2.get_data();
        assertEquals(data2.new_func_name, "new function name");
        assertEquals(data2.orig_func_name, "original function name");
        assertEquals(data2.parameters.size(), 2);
        assertEquals(data2.parameters.get(0).new_param_name, "new parameter name");
        assertEquals(data2.parameters.get(0).orig_param_name, "original parameter name");
        assertEquals(data2.parameters.get(1).new_param_name, "new parameter name2");
        assertEquals(data2.parameters.get(1).orig_param_name, "original parameter name2");
        assertEquals(data2.variables.size(), 2);
        assertEquals(data2.variables.get(0).new_var_name, "new variable name");
        assertEquals(data2.variables.get(0).orig_var_name, "original variable name");
        assertEquals(data2.variables.get(1).new_var_name, "new variable name2");
        assertEquals(data2.variables.get(1).orig_var_name, "original variable name2");
    }

    @Test
    void test_bf() throws Exception {
        String s1 = "This is markdown.\n" +
                   "{\n" +
                   "    \"new_func_name\": \"new function name\",\n" +
                   "    \"orig_func_name\": \"original function name\",\n" +
                   "    \"parameters\": [\n" +
                   "        {\n" +
                   "            \"new_param_name\": \"new parameter name\",\n" +
                   "            \"orig_param_name\": \"original parameter name\"\n" +
                   "        }\n" +
                   "    ],\n" +
                   "    \"variables\": [\n" +
                   "        {\n" +
                   "            \"new_var_name\": \"new variable name\",\n" +
                   "            \"orig_var_name\": \"original variable name\"\n" +
                   "        }\n" +
                   "    ]\n" +
                   "}\n" +
                   "```\n" +
                   "This is markdown.";
        JsonExtractor extractor = new JsonExtractor(s1);
        FuncParamVarJson data1 = extractor.get_data();
        assertEquals(data1.new_func_name, "new function name");
        assertEquals(data1.orig_func_name, "original function name");
        assertEquals(data1.parameters.size(), 1);
        assertEquals(data1.variables.size(), 1);
        assertEquals(data1.parameters.get(0).new_param_name, "new parameter name");
        assertEquals(data1.parameters.get(0).orig_param_name, "original parameter name");
        assertEquals(data1.variables.get(0).new_var_name, "new variable name");
        assertEquals(data1.variables.get(0).orig_var_name, "original variable name");

        String s2 = "This is markdown. ```cpp\nint main() {}\n```\n" +
                   "{\n" +
                   "    \"new_func_name\": \"new function name\",\n" +
                   "    \"orig_func_name\": \"original function name\",\n" +
                   "    \"parameters\": [\n" +
                   "        {\n" +
                   "            \"new_param_name\": \"new parameter name\",\n" +
                   "            \"orig_param_name\": \"original parameter name\"\n" +
                   "        },\n" +
                   "        {\n" +
                   "            \"new_param_name\": \"new parameter name2\",\n" +
                   "            \"orig_param_name\": \"original parameter name2\"\n" +
                   "        }\n" +
                   "    ],\n" +
                   "    \"variables\": [\n" +
                   "        {\n" +
                   "            \"new_var_name\": \"new variable name\",\n" +
                   "            \"orig_var_name\": \"original variable name\"\n" +
                   "        },\n" +
                   "        {\n" +
                   "            \"new_var_name\": \"new variable name2\",\n" +
                   "            \"orig_var_name\": \"original variable name2\"\n" +
                   "        }\n" +
                   "    ]\n" +
                   "}\n" +
                   "This is markdown. ```cpp\nint main() {}\n```\n";
        JsonExtractor extractor2 = new JsonExtractor(s2);
        FuncParamVarJson data2 = extractor2.get_data();
        assertEquals(data2.new_func_name, "new function name");
        assertEquals(data2.orig_func_name, "original function name");
        assertEquals(data2.parameters.size(), 2);
        assertEquals(data2.parameters.get(0).new_param_name, "new parameter name");
        assertEquals(data2.parameters.get(0).orig_param_name, "original parameter name");
        assertEquals(data2.parameters.get(1).new_param_name, "new parameter name2");
        assertEquals(data2.parameters.get(1).orig_param_name, "original parameter name2");
        assertEquals(data2.variables.size(), 2);
        assertEquals(data2.variables.get(0).new_var_name, "new variable name");
        assertEquals(data2.variables.get(0).orig_var_name, "original variable name");
        assertEquals(data2.variables.get(1).new_var_name, "new variable name2");
        assertEquals(data2.variables.get(1).orig_var_name, "original variable name2");
    }
}
