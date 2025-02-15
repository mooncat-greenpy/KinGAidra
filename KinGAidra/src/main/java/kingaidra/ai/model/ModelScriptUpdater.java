package kingaidra.ai.model;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
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
    private static String REGEX = "(<KinGAidra Marker For Update: v\\d+\\.\\d+\\.\\d+>(\\r\\n|\\n)).*";
    private static String SOURCE_SCRIPT = "kingaidra_chat.py";

    private GhidraScriptInfoManager script_mgr;
    private String new_code;

    public ModelScriptUpdater() {
        script_mgr = new GhidraScriptInfoManager();
        new_code = null;

        ResourceFile res_file = GhidraScriptUtil.findScriptByName(SOURCE_SCRIPT);
        if (res_file == null) {
            return;
        }
        File file = res_file.getFile(true);
        if (file == null) {
            return;
        }

        String content = read_file(file);
        Matcher matcher = match_marker(content);
        if (!matcher.find()) {
            return;
        }
        new_code = matcher.group(0);
    }

    public void update_scripts() {
        if (new_code == null) {
            return;
        }

        for (ResourceFile res_dir : GhidraScriptUtil.getScriptSourceDirectories()) {
            for (ResourceFile res_file : res_dir.listFiles()) {
                ScriptInfo info = script_mgr.getScriptInfo(res_file);
                if (info.getName().equals(SOURCE_SCRIPT)) {
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
        String updated_content = content.replace(target_code, new_code);
        write_file(target, updated_content);
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
