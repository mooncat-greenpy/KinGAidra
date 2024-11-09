package kingaidra.decom;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import kingaidra.decom.ai.Ai;
import kingaidra.decom.ai.Model;
import kingaidra.decom.ai.ModelByScript;
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

    private Model get_model(String name) {
        for (Model model : model_status.keySet()) {
            if (model.get_name().equals(name)) {
                return model;
            }
        }
        return null;
    }

    public String[] get_models() {
        return model_status.keySet().stream().map(Model::get_name).toArray(String[]::new);
    }

    public int get_models_len() {
        return model_status.size();
    }

    public boolean exist_model(String name) {
        return model_status.keySet().stream().anyMatch(p -> p.get_name().equals(name));
    }

    public String get_model_script(String name) {
        Model m = get_model(name);
        if (m == null) {
            return null;
        }
        return m.get_script();
    }

    public boolean get_model_status(String name) {
        Model m = get_model(name);
        if (m == null) {
            return false;
        }
        return model_status.get(m);
    }

    public void set_model_name(String name, String new_name) {
        Model m = get_model(name);
        if (m == null) {
            return;
        }
        m.set_name(new_name);
    }

    public void set_model_script(String name, String script_file) {
        Model m = get_model(name);
        if (m == null) {
            return;
        }
        m.set_script(script_file);
    }

    public void set_model_status(String name, boolean status) {
        Model m = get_model(name);
        if (m == null) {
            return;
        }
        model_status.replace(m, status);
    }

    public void add_model(String name, String script_file) {
        Model m = new ModelByScript(name, script_file);
        model_status.put(m, true);
    }

    public void remove_model(String name) {
        Model m = get_model(name);
        if (m == null) {
            return;
        }
        model_status.remove(m);
    }

    public DecomDiff guess(String name, DecomDiff diff) {
        Model m = get_model(name);
        if (m == null) {
            return null;
        }
        diff.set_model(m);
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
            DecomDiff guessed = guess(model.get_name(), diff.clone());
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
            DecomDiff guessed = guess(model.get_name(), diff.clone());
            if (guessed == null) {
                continue;
            }
            results.add(guessed);
        }
        return results.toArray(new DecomDiff[] {});
    }

    public DecomDiff guess(String name, Address addr) {
        DecomDiff diff = ghidra.get_decomdiff(addr);
        if (diff == null) {
            return null;
        }
        return guess(name, diff);
    }
}
