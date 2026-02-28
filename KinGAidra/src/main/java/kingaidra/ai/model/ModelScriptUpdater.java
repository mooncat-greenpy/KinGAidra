package kingaidra.ai.model;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import generic.jar.ResourceFile;
import ghidra.app.script.AbstractPythonScriptProvider;
import ghidra.app.script.GhidraScriptInfoManager;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.ScriptInfo;

public class ModelScriptUpdater {
    private static String[] CATEGORY = new String[]{"KinGAidra"};
    private static String REGEX = "(<KinGAidra Marker For Update: (?:(\\S+) )?v\\d+\\.\\d+\\.\\d+>(\\r\\n|\\n)).*";
    private static String DEFAULT_SOURCE_SCRIPT = "kingaidra_chat.py";
    private static String[] SOURCE_SCRIPTS = new String[]{
        DEFAULT_SOURCE_SCRIPT,
        "kingaidra_chat_langchain.py",
        "kingaidra_chat_codex.py",
    };

    private GhidraScriptInfoManager script_mgr;
    private Map<String, String> new_codes;

    public ModelScriptUpdater() {
        script_mgr = new GhidraScriptInfoManager();
        new_codes = new HashMap<>();

        for (String source_script : SOURCE_SCRIPTS) {
            ResourceFile res_file = GhidraScriptUtil.findScriptByName(source_script);
            if (res_file == null) {
                continue;
            }
            File file = res_file.getFile(true);
            if (file == null) {
                continue;
            }

            String content = read_file(file);
            Matcher matcher = match_marker(content);
            if (!matcher.find()) {
                continue;
            }
            new_codes.put(source_script, matcher.group(0));
        }
    }

    public void update_scripts() {
        if (new_codes.isEmpty()) {
            return;
        }
        Set<String> source_scripts = new HashSet<>();
        for (String name : SOURCE_SCRIPTS) {
            source_scripts.add(name);
        }

        for (ResourceFile res_dir : GhidraScriptUtil.getScriptSourceDirectories()) {
            for (ResourceFile res_file : res_dir.listFiles()) {
                ScriptInfo info = script_mgr.getScriptInfo(res_file);
                if (source_scripts.contains(info.getName())) {
                    continue;
                }
                GhidraScriptProvider provider = GhidraScriptUtil.getProvider(res_file);
                if (!(provider instanceof AbstractPythonScriptProvider)) {
                    continue;
                }
                if (!info.isCategory(CATEGORY)) {
                    continue;
                }

                File file = res_file.getFile(false);
                if (file == null) {
                    continue;
                }
                update_script(file);
            }
        }
    }

    private void update_script(File target) {
        String content = read_file(target);
        Matcher matcher = match_marker(content);
        if (!matcher.find()) {
            return;
        }

        String target_code = matcher.group(0);
        String source_script = marker_source_script(matcher);
        String new_code = new_codes.get(source_script);
        if (new_code == null) {
            return;
        }

        String updated_content = content.replace(target_code, new_code);
        write_file(target, updated_content);
    }

    private String marker_source_script(Matcher matcher) {
        String source_script = matcher.group(2);
        if (source_script == null || source_script.isEmpty()) {
            return DEFAULT_SOURCE_SCRIPT;
        }
        return source_script;
    }

    private Matcher match_marker(String str) {
        Pattern pattern = Pattern.compile(REGEX, Pattern.DOTALL);
        return pattern.matcher(str);
    }

    public static String read_file(File file) {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append(System.lineSeparator());
            }
        } catch (IOException e) {
        }
        return content.toString();
    }

    public static void write_file(File file, String content) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(content);
        } catch (IOException e) {
        }
    }
}
