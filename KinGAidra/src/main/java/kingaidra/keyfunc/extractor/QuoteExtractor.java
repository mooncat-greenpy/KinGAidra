package kingaidra.keyfunc.extractor;

import java.util.LinkedList;
import java.util.List;

public class QuoteExtractor {
    public List<String> strings;

    public QuoteExtractor(String s) {
        strings = extract_single_quote(s);
    }

    public List<String> get_strings() {
        return strings;
    }

    private List<String> extract_single_quote(String s) {
        List<String> quotes = new LinkedList<>();
        boolean in_code_block = false;
        boolean in_quote = false;
        StringBuilder current_quote = new StringBuilder();

        for (int i = 0; i < s.length(); i++) {
            if (s.startsWith("```", i)) {
                in_code_block = !in_code_block;
                i += 2;
                continue;
            }

            if (!in_code_block) {
                if (s.charAt(i) == '`') {
                    if (in_quote) {
                        quotes.add(current_quote.toString());
                        current_quote.setLength(0);
                    }
                    in_quote = !in_quote;
                } else if (in_quote) {
                    current_quote.append(s.charAt(i));
                }
            }
        }

        return quotes;
    }
}
