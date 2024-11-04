package kingaidra.decom;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import kingaidra.decom.ai.Model;

public class DecomDiff implements Cloneable {
    private Address addr;
    private String src_code;
    private Model model;

    private DiffPair name;
    private Map<Long, DiffPair> params;
    private Map<Long, DiffPair> vars;

    public DecomDiff(Address addr, String old_name, String src_code) {
        this.addr = addr;
        this.model = null;
        this.src_code = src_code;

        this.name = new DiffPair(0, old_name);
        params = new HashMap<>();
        vars = new HashMap<>();
    }

    public DecomDiff(Address addr, DiffPair name, String src_code) {
        this.addr = addr;
        this.model = null;
        this.src_code = src_code;

        this.name = name;
        params = new HashMap<>();
        vars = new HashMap<>();
    }

    @Override
    public DecomDiff clone() {
        DecomDiff diff = new DecomDiff(addr, name.clone(), src_code);
        diff.set_model(model);
        for (DiffPair pair : diff.get_params()) {
            diff.add_param(pair.clone());
        }
        for (DiffPair pair : diff.get_vars()) {
            diff.add_var(pair.clone());
        }
        return diff;
    }

    public Address get_addr() {
        return addr;
    }

    public String get_src_code() {
        return src_code;
    }

    public Model get_model() {
        return model;
    }

    public void set_model(Model model) {
        this.model = model;
    }

    public DiffPair get_name() {
        return name;
    }

    public void set_name(String name) {
        this.name.set_new_name(name);
    }

    public DiffPair get_param(long id) {
        return params.get(id);
    }

    public Collection<DiffPair> get_params() {
        return params.values();
    }

    public int get_params_len() {
        return params.size();
    }

    public void add_param(DiffPair pair) {
        params.put(pair.get_id(), pair);
    }

    public void delete_param(long id) {
        params.remove(id);
    }

    public void set_param_new_name(String old_name, String new_name) {
        for (DiffPair pair : params.values()) {
            if (!pair.get_old_name().equals(old_name)) {
                continue;
            }
            pair.set_new_name(new_name);
        }
    }

    public DiffPair get_var(long id) {
        return vars.get(id);
    }

    public Collection<DiffPair> get_vars() {
        return vars.values();
    }

    public int get_vars_len() {
        return vars.size();
    }

    public void add_var(DiffPair pair) {
        vars.put(pair.get_id(), pair);
    }

    public void delete_var(long id) {
        vars.remove(id);
    }

    public void set_var_new_name(String old_name, String new_name) {
        for (DiffPair pair : vars.values()) {
            if (!pair.get_old_name().equals(old_name)) {
                continue;
            }
            pair.set_new_name(new_name);
        }
    }
}
