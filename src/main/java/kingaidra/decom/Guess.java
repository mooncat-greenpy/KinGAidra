package kingaidra.decom;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import kingaidra.decom.ai.Ai;
import kingaidra.decom.ai.Model;
import kingaidra.ghidra.GhidraUtil;

public class Guess {
    private Ai ai;
    private GhidraUtil ghidra;
    private Map<Model, Boolean> model_status;

    public Guess(GhidraUtil ghidra, Ai ai, Model[] models) {
        this.ghidra = ghidra;
        this.ai = ai;
        model_status = new HashMap<>();
        for (Model model : models) {
            model_status.put(model, true);
        }
    }

    public Model[] get_models() {
        return model_status.keySet().toArray(new Model[] {});
    }

    public int get_models_len() {
        return model_status.size();
    }

    public boolean get_model_status(Model model) {
        return model_status.get(model);
    }

    public void set_model_status(Model model, boolean status) {
        model_status.replace(model, status);
    }

    public DecomDiff guess(Model model, DecomDiff diff) {
        diff.set_model(model);
        diff = ai.guess(diff);
        return diff;
    }

    public DecomDiff[] guess_all(Address addr) {
        List<DecomDiff> results = new ArrayList<>();
        DecomDiff diff = ghidra.get_decomdiff(addr);
        if (diff == null) {
            return results.toArray(new DecomDiff[] {});
        }
        for (Model model : model_status.keySet()) {
            DecomDiff guessed = guess(model, diff.clone());
            if (guessed == null) {
                continue;
            }
            results.add(guessed);
        }
        return results.toArray(new DecomDiff[] {});
    }

    public DecomDiff[] guess_selected(Address addr) {
        List<DecomDiff> results = new ArrayList<>();
        DecomDiff diff = ghidra.get_decomdiff(addr);
        if (diff == null) {
            return results.toArray(new DecomDiff[] {});
        }
        for (Model model : model_status.keySet()) {
            if (!model_status.get(model)) {
                continue;
            }
            DecomDiff guessed = guess(model, diff.clone());
            if (guessed == null) {
                continue;
            }
            results.add(guessed);
        }
        return results.toArray(new DecomDiff[] {});
    }

    public DecomDiff guess(Model model, Address addr) {
        DecomDiff diff = ghidra.get_decomdiff(addr);
        if (diff == null) {
            return null;
        }
        return guess(model, diff);
    }
}
