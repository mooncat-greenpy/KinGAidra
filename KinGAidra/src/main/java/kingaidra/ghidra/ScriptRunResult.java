package kingaidra.ghidra;

public final class ScriptRunResult {
    private final boolean success;
    private final String stdout;
    private final String stderr;

    ScriptRunResult(boolean success, String stdout, String stderr) {
        this.success = success;
        this.stdout = stdout == null ? "" : stdout;
        this.stderr = stderr == null ? "" : stderr;
    }

    public boolean get_success() {
        return success;
    }

    public String get_stdout() {
        return stdout;
    }

    public String get_stderr() {
        return stderr;
    }
}
