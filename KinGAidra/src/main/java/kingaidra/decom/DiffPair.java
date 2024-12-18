package kingaidra.decom;

public class DiffPair implements Cloneable {
    private long id;
    private String var_name;
    private String new_name;

    public DiffPair(long id, String name) {
        this.id = id;
        this.var_name = name;
        new_name = name;
    }

    public DiffPair(long id, String name, String new_name) {
        this.id = id;
        this.var_name = name;
        this.new_name = new_name;
    }

    @Override
    public DiffPair clone() {
        DiffPair pair = new DiffPair(id, var_name, new_name);
        return pair;
    }

    public long get_id() {
        return id;
    }

    public String get_var_name() {
        return var_name;
    }

    public String get_new_name() {
        return new_name;
    }

    public void set_new_name(String new_name) {
        this.new_name = new_name;
    }
}
