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
        String scriptName = "run_script_test.py";
        String inlineScriptName = "run_script_inline_test.py";
        Path scriptDir = new File(GhidraScriptUtil.USER_SCRIPTS_DIR).toPath();
        Files.createDirectories(scriptDir);
        Path scriptPath = scriptDir.resolve(scriptName);

        String script = ""
                + "#@category Test\n"
                + "import sys\n"
                + "sys.stdout.write(\"OUT:hello\\n\")\n"
                + "sys.stderr.write(\"ERR:boom\\n\")\n";
        String inlineScript = ""
                + "#@category Test\n"
                + "import sys\n"
                + "sys.stdout.write(\"OUT:inline\\n\")\n"
                + "sys.stderr.write(\"ERR:inline\\n\")\n";

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
