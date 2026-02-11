package kingaidra.chat.gui;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MarkdownPlantUmlExtractorTest {
    @Test
    void test_split_segments() {
        String markdown = "# title\n" +
                "before\n" +
                "```plantuml\n" +
                "Alice -> Bob: hello\n" +
                "```\n" +
                "middle\n" +
                "```cpp\n" +
                "int main() { return 0; }\n" +
                "```\n" +
                "```puml\n" +
                "@startuml\n" +
                "Bob -> Alice: world\n" +
                "@enduml\n" +
                "```\n" +
                "after\n";

        MarkdownPlantUmlExtractor extractor = new MarkdownPlantUmlExtractor();
        List<MarkdownPlantUmlExtractor.Segment> segments = extractor.split_segments(markdown);

        assertEquals(5, segments.size());
        assertFalse(segments.get(0).is_plantuml());
        assertTrue(segments.get(1).is_plantuml());
        assertFalse(segments.get(2).is_plantuml());
        assertTrue(segments.get(3).is_plantuml());
        assertFalse(segments.get(4).is_plantuml());
        assertTrue(segments.get(1).get_content().contains("Alice -> Bob: hello"));
        assertTrue(segments.get(2).get_content().contains("```cpp"));
    }

    @Test
    void test_split_segments_without_plantuml() {
        String markdown = "hello\n```cpp\nint v = 1;\n```\nworld";
        MarkdownPlantUmlExtractor extractor = new MarkdownPlantUmlExtractor();
        List<MarkdownPlantUmlExtractor.Segment> segments = extractor.split_segments(markdown);

        assertEquals(1, segments.size());
        assertFalse(segments.get(0).is_plantuml());
        assertEquals(markdown, segments.get(0).get_content());
    }
}
