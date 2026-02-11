package kingaidra.chat.gui;

import java.util.Arrays;
import java.util.regex.Pattern;

import com.vladsch.flexmark.ext.tables.TableBlock;
import com.vladsch.flexmark.ext.tables.TableCell;
import com.vladsch.flexmark.ext.tables.TablesExtension;
import com.vladsch.flexmark.html.AttributeProvider;
import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.html.IndependentAttributeProviderFactory;
import com.vladsch.flexmark.html.renderer.AttributablePart;
import com.vladsch.flexmark.html.renderer.LinkResolverContext;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.ast.Node;
import com.vladsch.flexmark.util.data.MutableDataSet;
import com.vladsch.flexmark.util.html.MutableAttributes;

public class MarkdownHtmlRenderer {
    private static final Pattern TABLE_HEADER_LINE = Pattern.compile("^\\s*\\|.+\\|\\s*$");
    private static final Pattern TABLE_SEPARATOR_LINE =
            Pattern.compile("^\\s*\\|\\s*:?-{3,}:?(\\s*\\|\\s*:?-{3,}:?)*\\s*\\|\\s*$");

    private final Parser parser;
    private final HtmlRenderer renderer;

    public MarkdownHtmlRenderer() {
        MutableDataSet options = new MutableDataSet();
        options.set(Parser.EXTENSIONS, Arrays.asList(TablesExtension.create()));
        options.set(TablesExtension.APPEND_MISSING_COLUMNS, true);
        options.set(TablesExtension.DISCARD_EXTRA_COLUMNS, true);
        options.set(TablesExtension.WITH_CAPTION, false);

        parser = Parser.builder(options).build();
        renderer = HtmlRenderer.builder(options)
                .attributeProviderFactory(new SwingTableAttributeProviderFactory())
                .build();
    }

    public String render(String markdown) {
        String normalized = normalize_markdown_tables(markdown == null ? "" : markdown);
        return renderer.render(parser.parse(normalized));
    }

    private String normalize_markdown_tables(String markdown) {
        String[] lines = markdown.split("\\R", -1);
        StringBuilder out = new StringBuilder(markdown.length() + 16);
        for (int i = 0; i < lines.length; i++) {
            boolean table_start = i + 1 < lines.length
                    && TABLE_HEADER_LINE.matcher(lines[i]).matches()
                    && TABLE_SEPARATOR_LINE.matcher(lines[i + 1]).matches();
            if (table_start && i > 0 && !lines[i - 1].trim().isEmpty()) {
                out.append('\n');
            }
            out.append(lines[i]);
            if (i < lines.length - 1) {
                out.append('\n');
            }
        }
        return out.toString();
    }

    private static class SwingTableAttributeProviderFactory
            extends IndependentAttributeProviderFactory {
        @Override
        public AttributeProvider apply(LinkResolverContext context) {
            return new AttributeProvider() {
                @Override
                public void setAttributes(Node node, AttributablePart part, MutableAttributes attributes) {
                    if (AttributablePart.NODE != part) {
                        return;
                    }
                    if (node instanceof TableBlock) {
                        attributes.replaceValue("border", "1");
                        attributes.replaceValue("cellpadding", "4");
                        attributes.replaceValue("cellspacing", "0");
                    }
                    if (node instanceof TableCell) {
                        attributes.replaceValue("valign", "top");
                    }
                }
            };
        }
    }
}
