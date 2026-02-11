package kingaidra.chat.gui;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

import com.vladsch.flexmark.ast.FencedCodeBlock;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.ast.Node;
import com.vladsch.flexmark.util.ast.NodeVisitor;
import com.vladsch.flexmark.util.ast.VisitHandler;
import com.vladsch.flexmark.util.data.MutableDataSet;

public class MarkdownPlantUmlExtractor {

    public enum SegmentType {
        MARKDOWN,
        PLANTUML
    }

    public static class Segment {
        private final SegmentType type;
        private final String content;

        Segment(SegmentType type, String content) {
            this.type = type;
            this.content = content;
        }

        public String get_content() {
            return content;
        }

        public boolean is_plantuml() {
            return SegmentType.PLANTUML.equals(type);
        }
    }

    private final Parser parser;

    public MarkdownPlantUmlExtractor() {
        MutableDataSet options = new MutableDataSet();
        parser = Parser.builder(options).build();
    }

    public List<Segment> split_segments(String markdown) {
        String target = markdown == null ? "" : markdown;
        List<FencedCodeBlock> uml_blocks = get_plantuml_fences(target);
        if (uml_blocks.isEmpty()) {
            List<Segment> parts = new LinkedList<>();
            parts.add(new Segment(SegmentType.MARKDOWN, target));
            return parts;
        }

        uml_blocks.sort(Comparator.comparingInt(Node::getStartOffset));
        int cursor = 0;
        List<Segment> parts = new LinkedList<>();
        for (FencedCodeBlock block : uml_blocks) {
            int start = clamp_offset(block.getStartOffset(), target.length());
            int end = clamp_offset(block.getEndOffset(), target.length());
            if (start < cursor) {
                continue;
            }

            if (cursor < start) {
                parts.add(new Segment(SegmentType.MARKDOWN, target.substring(cursor, start)));
            }
            parts.add(new Segment(SegmentType.PLANTUML, block.getContentChars().toString()));
            cursor = Math.max(cursor, end);
        }
        if (cursor < target.length()) {
            parts.add(new Segment(SegmentType.MARKDOWN, target.substring(cursor)));
        }

        if (parts.isEmpty()) {
            parts.add(new Segment(SegmentType.MARKDOWN, target));
        }
        return parts;
    }

    private int clamp_offset(int offset, int length) {
        return Math.max(0, Math.min(offset, length));
    }

    private List<FencedCodeBlock> get_plantuml_fences(String markdown) {
        List<FencedCodeBlock> blocks = new ArrayList<>();
        NodeVisitor visitor = new NodeVisitor(
                new VisitHandler<>(FencedCodeBlock.class, fenced_code -> {
                    if (is_plantuml_fence(fenced_code)) {
                        blocks.add(fenced_code);
                    }
                }));
        visitor.visit(parser.parse(markdown));
        return blocks;
    }

    private boolean is_plantuml_fence(FencedCodeBlock block) {
        String info = block.getInfo().toString().trim().toLowerCase(Locale.ROOT);
        String lang = info;
        int space_idx = info.indexOf(' ');
        if (space_idx >= 0) {
            lang = info.substring(0, space_idx).trim();
        }
        if ("plantuml".equals(lang) || "puml".equals(lang) || "uml".equals(lang)) {
            return true;
        }

        String content = block.getContentChars().toString();
        String[] lines = content.split("\\R");
        for (String line : lines) {
            if (line.trim().toLowerCase(Locale.ROOT).startsWith("@start")) {
                return true;
            }
        }
        return false;
    }
}
