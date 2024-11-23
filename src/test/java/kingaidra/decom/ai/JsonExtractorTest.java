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
        JsonExtractor<FuncParamVarJson> extractor = new JsonExtractor(s1, FuncParamVarJson.class);
        FuncParamVarJson data1 = extractor.get_data();
        assertEquals(data1.new_func_name, "new function name");
        assertEquals(data1.orig_func_name, "original function name");
        assertEquals(data1.parameters.size(), 1);
        assertEquals(data1.variables.size(), 1);
        assertEquals(data1.parameters.get(0).get_new_param_name(), "new parameter name");
        assertEquals(data1.parameters.get(0).get_orig_param_name(), "original parameter name");
        assertEquals(data1.variables.get(0).get_new_var_name(), "new variable name");
        assertEquals(data1.variables.get(0).get_orig_var_name(), "original variable name");

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
        JsonExtractor<FuncParamVarJson> extractor2 = new JsonExtractor(s2, FuncParamVarJson.class);
        FuncParamVarJson data2 = extractor2.get_data();
        assertEquals(data2.new_func_name, "new function name");
        assertEquals(data2.orig_func_name, "original function name");
        assertEquals(data2.parameters.size(), 2);
        assertEquals(data2.parameters.get(0).get_new_param_name(), "new parameter name");
        assertEquals(data2.parameters.get(0).get_orig_param_name(), "original parameter name");
        assertEquals(data2.parameters.get(1).get_new_param_name(), "new parameter name2");
        assertEquals(data2.parameters.get(1).get_orig_param_name(), "original parameter name2");
        assertEquals(data2.variables.size(), 2);
        assertEquals(data2.variables.get(0).get_new_var_name(), "new variable name");
        assertEquals(data2.variables.get(0).get_orig_var_name(), "original variable name");
        assertEquals(data2.variables.get(1).get_new_var_name(), "new variable name2");
        assertEquals(data2.variables.get(1).get_orig_var_name(), "original variable name2");

        String s3 = "[\n" +
                   "    {\n" +
                   "        \"new_datatype\": \"new datatype name\",\n" +
                   "        \"orig_datatype\": \"original datatype name\",\n" +
                   "        \"var_name\": \"variable name\"\n" +
                   "    }\n" +
                   "]";
        JsonExtractor<DataTypeListJson> extractor3 = new JsonExtractor(s3, DataTypeListJson.class);
        DataTypeListJson data3 = extractor3.get_data();
        assertEquals(data3.size(), 1);
        assertEquals(data3.get(0).get_new_datatype(), "new datatype name");
        assertEquals(data3.get(0).get_orig_datatype(), "original datatype name");
        assertEquals(data3.get(0).get_var_name(), "variable name");

        String s4 = "[\n" +
                   "    {\n" +
                   "        \"new_datatype\": \"new datatype name\",\n" +
                   "        \"orig_datatype\": \"original datatype name\",\n" +
                   "        \"var_name\": \"variable name\"\n" +
                   "    },\n" +
                   "    {\n" +
                   "        \"new_datatype\": \"new datatype name2\",\n" +
                   "        \"orig_datatype\": \"original datatype name2\",\n" +
                   "        \"var_name\": \"variable name2\"\n" +
                   "    }\n" +
                   "]";
        JsonExtractor<DataTypeListJson> extractor4 = new JsonExtractor(s4, DataTypeListJson.class);
        DataTypeListJson data4 = extractor4.get_data();
        assertEquals(data4.size(), 2);
        assertEquals(data4.get(0).get_new_datatype(), "new datatype name");
        assertEquals(data4.get(0).get_orig_datatype(), "original datatype name");
        assertEquals(data4.get(0).get_var_name(), "variable name");
        assertEquals(data4.get(1).get_new_datatype(), "new datatype name2");
        assertEquals(data4.get(1).get_orig_datatype(), "original datatype name2");
        assertEquals(data4.get(1).get_var_name(), "variable name2");
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
        JsonExtractor<FuncParamVarJson> extractor = new JsonExtractor(s1, FuncParamVarJson.class);
        FuncParamVarJson data1 = extractor.get_data();
        assertEquals(data1.new_func_name, "new function name");
        assertEquals(data1.orig_func_name, "original function name");
        assertEquals(data1.parameters.size(), 1);
        assertEquals(data1.variables.size(), 1);
        assertEquals(data1.parameters.get(0).get_new_param_name(), "new parameter name");
        assertEquals(data1.parameters.get(0).get_orig_param_name(), "original parameter name");
        assertEquals(data1.variables.get(0).get_new_var_name(), "new variable name");
        assertEquals(data1.variables.get(0).get_orig_var_name(), "original variable name");

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
        JsonExtractor<FuncParamVarJson> extractor2 = new JsonExtractor(s2, FuncParamVarJson.class);
        FuncParamVarJson data2 = extractor2.get_data();
        assertEquals(data2.new_func_name, "new function name");
        assertEquals(data2.orig_func_name, "original function name");
        assertEquals(data2.parameters.size(), 2);
        assertEquals(data2.parameters.get(0).get_new_param_name(), "new parameter name");
        assertEquals(data2.parameters.get(0).get_orig_param_name(), "original parameter name");
        assertEquals(data2.parameters.get(1).get_new_param_name(), "new parameter name2");
        assertEquals(data2.parameters.get(1).get_orig_param_name(), "original parameter name2");
        assertEquals(data2.variables.size(), 2);
        assertEquals(data2.variables.get(0).get_new_var_name(), "new variable name");
        assertEquals(data2.variables.get(0).get_orig_var_name(), "original variable name");
        assertEquals(data2.variables.get(1).get_new_var_name(), "new variable name2");
        assertEquals(data2.variables.get(1).get_orig_var_name(), "original variable name2");

        String s3 = "```json\n" +
                   "[\n" +
                   "    {\n" +
                   "        \"new_datatype\": \"new datatype name\",\n" +
                   "        \"orig_datatype\": \"original datatype name\",\n" +
                   "        \"var_name\": \"variable name\"\n" +
                   "    }\n" +
                   "]\n" +
                   "```";
        JsonExtractor<DataTypeListJson> extractor3 = new JsonExtractor(s3, DataTypeListJson.class);
        DataTypeListJson data3 = extractor3.get_data();
        assertEquals(data3.size(), 1);
        assertEquals(data3.get(0).get_new_datatype(), "new datatype name");
        assertEquals(data3.get(0).get_orig_datatype(), "original datatype name");
        assertEquals(data3.get(0).get_var_name(), "variable name");

        String s4 = "This is markdown. ```cpp\nint main() {}\n```\n" +
                   "```json\n" +
                   "[\n" +
                   "    {\n" +
                   "        \"new_datatype\": \"new datatype name\",\n" +
                   "        \"orig_datatype\": \"original datatype name\",\n" +
                   "        \"var_name\": \"variable name\"\n" +
                   "    },\n" +
                   "    {\n" +
                   "        \"new_datatype\": \"new datatype name2\",\n" +
                   "        \"orig_datatype\": \"original datatype name2\",\n" +
                   "        \"var_name\": \"variable name2\"\n" +
                   "    }\n" +
                   "]\n" +
                   "```\n" +
                   "This is markdown. ```cpp\nint main() {}\n```\n";
        JsonExtractor<DataTypeListJson> extractor4 = new JsonExtractor(s4, DataTypeListJson.class);
        DataTypeListJson data4 = extractor4.get_data();
        assertEquals(data4.size(), 2);
        assertEquals(data4.get(0).get_new_datatype(), "new datatype name");
        assertEquals(data4.get(0).get_orig_datatype(), "original datatype name");
        assertEquals(data4.get(0).get_var_name(), "variable name");
        assertEquals(data4.get(1).get_new_datatype(), "new datatype name2");
        assertEquals(data4.get(1).get_orig_datatype(), "original datatype name2");
        assertEquals(data4.get(1).get_var_name(), "variable name2");
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
        JsonExtractor<FuncParamVarJson> extractor = new JsonExtractor(s1, FuncParamVarJson.class);
        FuncParamVarJson data1 = extractor.get_data();
        assertEquals(data1.new_func_name, "new function name");
        assertEquals(data1.orig_func_name, "original function name");
        assertEquals(data1.parameters.size(), 1);
        assertEquals(data1.variables.size(), 1);
        assertEquals(data1.parameters.get(0).get_new_param_name(), "new parameter name");
        assertEquals(data1.parameters.get(0).get_orig_param_name(), "original parameter name");
        assertEquals(data1.variables.get(0).get_new_var_name(), "new variable name");
        assertEquals(data1.variables.get(0).get_orig_var_name(), "original variable name");

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
        JsonExtractor<FuncParamVarJson> extractor2 = new JsonExtractor(s2, FuncParamVarJson.class);
        FuncParamVarJson data2 = extractor2.get_data();
        assertEquals(data2.new_func_name, "new function name");
        assertEquals(data2.orig_func_name, "original function name");
        assertEquals(data2.parameters.size(), 2);
        assertEquals(data2.parameters.get(0).get_new_param_name(), "new parameter name");
        assertEquals(data2.parameters.get(0).get_orig_param_name(), "original parameter name");
        assertEquals(data2.parameters.get(1).get_new_param_name(), "new parameter name2");
        assertEquals(data2.parameters.get(1).get_orig_param_name(), "original parameter name2");
        assertEquals(data2.variables.size(), 2);
        assertEquals(data2.variables.get(0).get_new_var_name(), "new variable name");
        assertEquals(data2.variables.get(0).get_orig_var_name(), "original variable name");
        assertEquals(data2.variables.get(1).get_new_var_name(), "new variable name2");
        assertEquals(data2.variables.get(1).get_orig_var_name(), "original variable name2");

        String s3 = "This is markdown.\n" +
                   "[\n" +
                   "    {\n" +
                   "        \"new_datatype\": \"new datatype name\",\n" +
                   "        \"orig_datatype\": \"original datatype name\",\n" +
                   "        \"var_name\": \"variable name\"\n" +
                   "    }\n" +
                   "]\n" +
                   "```\n" +
                   "This is markdown.";
        JsonExtractor<DataTypeListJson> extractor3 = new JsonExtractor(s3, DataTypeListJson.class);
        DataTypeListJson data3 = extractor3.get_data();
        assertEquals(data3.size(), 1);
        assertEquals(data3.get(0).get_new_datatype(), "new datatype name");
        assertEquals(data3.get(0).get_orig_datatype(), "original datatype name");
        assertEquals(data3.get(0).get_var_name(), "variable name");

        String s4 = "This is markdown. ```cpp\nint main() {}\n```\n" +
                   "[\n" +
                   "    {\n" +
                   "        \"new_datatype\": \"new datatype name\",\n" +
                   "        \"orig_datatype\": \"original datatype name\",\n" +
                   "        \"var_name\": \"variable name\"\n" +
                   "    },\n" +
                   "    {\n" +
                   "        \"new_datatype\": \"new datatype name2\",\n" +
                   "        \"orig_datatype\": \"original datatype name2\",\n" +
                   "        \"var_name\": \"variable name2\"\n" +
                   "    }\n" +
                   "]\n" +
                   "This is markdown. ```cpp\nint main() {}\n```\n";
        JsonExtractor<DataTypeListJson> extractor4 = new JsonExtractor(s4, DataTypeListJson.class);
        DataTypeListJson data4 = extractor4.get_data();
        assertEquals(data4.size(), 2);
        assertEquals(data4.get(0).get_new_datatype(), "new datatype name");
        assertEquals(data4.get(0).get_orig_datatype(), "original datatype name");
        assertEquals(data4.get(0).get_var_name(), "variable name");
        assertEquals(data4.get(1).get_new_datatype(), "new datatype name2");
        assertEquals(data4.get(1).get_orig_datatype(), "original datatype name2");
        assertEquals(data4.get(1).get_var_name(), "variable name2");
    }
}
