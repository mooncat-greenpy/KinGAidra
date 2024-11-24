package kingaidra.decom.ai;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ClangExtractorTest {

    @Test
    void test_md() throws Exception {
        String s1 = "```cpp\n" +
                   "#include <stdio.h>\n" +
                   "int main(int argc, char **argv) {\n" +
                   "  printf(\"Hello, world,\\n" + //
                   "\");\n" +
                   "}\n" +
                   "```";
        ClangExtractor extractor1 = new ClangExtractor(s1);
        String data1 = extractor1.get_data();
        assertEquals(data1, "\n#include <stdio.h>\n" +
                        "int main(int argc, char **argv) {\n" +
                        "  printf(\"Hello, world,\\n" +
                        "\");\n" +
                        "}\n");

        String s2 = "```c\n" +
                   "#include <stdio.h>\n" +
                   "int main(int argc, char **argv) {\n" +
                   "  printf(\"Hello, world,\\n" + //
                   "\");\n" +
                   "}\n" +
                   "```";
        ClangExtractor extractor2 = new ClangExtractor(s2);
        String data2 = extractor2.get_data();
        assertEquals(data2, "\n#include <stdio.h>\n" +
                        "int main(int argc, char **argv) {\n" +
                        "  printf(\"Hello, world,\\n" +
                        "\");\n" +
                        "}\n");
    }
}
