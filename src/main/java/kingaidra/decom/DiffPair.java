package kingaidra.decom;

public class DiffPair implements Cloneable {
    private long id;
    private String old_name;
    private String new_name;

    public DiffPair(long id, String name) {
        this.id = id;
        old_name = name;
        new_name = name;
    }

    public DiffPair(long id, String old_name, String new_name) {
        this.id = id;
        this.old_name = old_name;
        this.new_name = new_name;
    }

    @Override
    public DiffPair clone() {
        DiffPair pair = new DiffPair(id, old_name, new_name);
        return pair;
    }

    public long get_id() {
        return id;
    }

    public String get_old_name() {
        return old_name;
    }

    public String get_new_name() {
        return new_name;
    }

    public void set_new_name(String new_name) {
        this.new_name = new_name;
    }
}
