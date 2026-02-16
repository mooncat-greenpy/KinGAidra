package kingaidra.decom;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class LlmDecompileTest {

    @Test
    public void normalize_code_returns_null_for_null() {
        assertNull(LlmDecompile.normalize_code(null));
    }

    @Test
    public void normalize_code_extracts_c_code_block() {
        String raw = "Result:\n```c\nint main() {\n    return 0;\n}\n```";
        String expected = "int main() {\n    return 0;\n}";
        assertEquals(expected, LlmDecompile.normalize_code(raw));
    }

    @Test
    public void normalize_code_falls_back_to_trimmed_text() {
        assertEquals("int x = 1;", LlmDecompile.normalize_code("  int x = 1;  "));
    }
}
