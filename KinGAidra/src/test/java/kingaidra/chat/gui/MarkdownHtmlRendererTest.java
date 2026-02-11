package kingaidra.chat.gui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class MarkdownHtmlRendererTest {
    @Test
    void test_render_table_to_html() {
        String markdown = "| Name | Value |\n"
                + "| --- | --- |\n"
                + "| alpha | 1 |\n"
                + "| beta | 2 |\n";
        MarkdownHtmlRenderer renderer = new MarkdownHtmlRenderer();
        String html = renderer.render(markdown);

        assertTrue(html.contains("<table"));
        assertTrue(html.contains("<th"));
        assertTrue(html.contains("<td"));
        assertTrue(html.contains("border=\"1\""));
        assertTrue(html.contains("cellpadding=\"4\""));
        assertTrue(html.contains("cellspacing=\"0\""));
    }

    @Test
    void test_render_table_after_hard_line_break() {
        String markdown = "**2. Evidence table**  \n"
                + "| Arrow | Evidence |\n"
                + "| --- | --- |\n"
                + "| A | B |\n";
        MarkdownHtmlRenderer renderer = new MarkdownHtmlRenderer();
        String html = renderer.render(markdown);

        assertTrue(html.contains("<table"));
        assertTrue(html.contains("<strong>2. Evidence table</strong>"));
    }
}
