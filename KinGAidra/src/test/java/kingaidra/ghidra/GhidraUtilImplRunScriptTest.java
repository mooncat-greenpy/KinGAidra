package kingaidra.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.testutil.GhidraTestUtil;

class GhidraUtilImplRunScriptTest {

    @Test
    void test_run_script_captures_stdout_and_stderr() throws Exception {
        GhidraTestUtil util = new GhidraTestUtil();
        Program program = util.create_program();
        GhidraUtilImpl ghidra = new GhidraUtilImpl(program, TaskMonitor.DUMMY);

        GhidraScriptUtil.acquireBundleHostReference();
        String scriptName = "RunScriptTest.java";
        String inlineScriptName = "RunScriptInlineTest.java";
        Path scriptDir = new File(GhidraScriptUtil.USER_SCRIPTS_DIR).toPath();
        Files.createDirectories(scriptDir);
        Path scriptPath = scriptDir.resolve(scriptName);

        String script = ""
                + "//@category Test\n"
                + "import ghidra.app.script.GhidraScript;\n"
                + "public class RunScriptTest extends GhidraScript {\n"
                + "    @Override\n"
                + "    public void run() throws Exception {\n"
                + "        println(\"OUT:hello\");\n"
                + "        printerr(\"ERR:boom\");\n"
                + "    }\n"
                + "}\n";
        String inlineScript = ""
                + "//@category Test\n"
                + "import ghidra.app.script.GhidraScript;\n"
                + "public class RunScriptInlineTest extends GhidraScript {\n"
                + "    @Override\n"
                + "    public void run() throws Exception {\n"
                + "        println(\"OUT:inline\");\n"
                + "        printerr(\"ERR:inline\");\n"
                + "    }\n"
                + "}\n";

        boolean existed = Files.exists(scriptPath);
        byte[] original = existed ? Files.readAllBytes(scriptPath) : null;
        try {
            Files.write(scriptPath, script.getBytes(StandardCharsets.UTF_8));

            assertTrue(GhidraScriptUtil.findScriptByName(scriptName) != null,
                    "Script not found: " + scriptName);
            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(
                    GhidraScriptUtil.findScriptByName(scriptName));
            assertTrue(provider != null, "Provider not found for: " + scriptName);

            ScriptRunResult result = ghidra.run_script(scriptName);
            assertTrue(result.get_success(),
                    "stdout=[" + result.get_stdout() + "], stderr=[" + result.get_stderr() + "]");
            assertEquals("OUT:hello\n", result.get_stdout());
            assertEquals("ERR:boom\n", result.get_stderr());

            Set<String> beforeNames = listScriptNames(scriptDir);
            ScriptRunResult inlineResult = ghidra.run_script(inlineScriptName, inlineScript);
            assertTrue(inlineResult.get_success(),
                    "stdout=[" + inlineResult.get_stdout() + "], stderr=[" + inlineResult.get_stderr() + "]");
            assertEquals("OUT:inline\n", inlineResult.get_stdout());
            assertEquals("ERR:inline\n", inlineResult.get_stderr());
            assertTrue(!Files.exists(scriptDir.resolve(inlineScriptName)),
                    "Inline script file should be deleted after execution: " + inlineScriptName);
            Set<String> afterNames = listScriptNames(scriptDir);
            assertEquals(beforeNames, afterNames, "Inline script should not leave files behind");
        } finally {
            if (existed) {
                Files.write(scriptPath, original);
            } else {
                Files.deleteIfExists(scriptPath);
            }
            GhidraScriptUtil.releaseBundleHostReference();
        }
    }

    private static Set<String> listScriptNames(Path scriptDir) throws Exception {
        try (Stream<Path> stream = Files.list(scriptDir)) {
            return stream.map(path -> path.getFileName().toString())
                    .collect(Collectors.toSet());
        }
    }
}
