package kingaidra.decom.extractor;

public class ClangExtractor {

    private String data;

    public ClangExtractor(String s) {
        data = extract_cpp_md(s);
        if (data != null) {
            return;
        }
    }

    public String get_data() {
        return data;
    }

    private String extract_cpp_md(String s) {
        String pre = "```cpp";
        String post = "```";
        int start = s.indexOf(pre);
        if (start < 0) {
            pre = "```c";
            start = s.indexOf(pre);
            if (start < 0) {
                pre = "```";
                start = s.indexOf(pre);
                if (start < 0) {
                    return null;
                }
            }
        }
        start += pre.length();
        int end = s.lastIndexOf(post);
        if (end < 0) {
            return null;
        }
        return s.substring(start, end);
    }
}
