package kingaidra.decom;

import kingaidra.ghidra.GhidraUtil;

public class Refactor {
    private GhidraUtil ghidra;

    public Refactor(GhidraUtil ghidra) {
        this.ghidra = ghidra;
    }

    public void refact(DecomDiff diff) {
        ghidra.refact(diff);
    }
}
