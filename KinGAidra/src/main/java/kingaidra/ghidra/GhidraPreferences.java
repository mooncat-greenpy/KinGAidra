package kingaidra.ghidra;

public interface GhidraPreferences<T> {
    public static final String BASE = "kingaidra.";

    public T[] get_list();

    public T get(String key);

    public void store(String key, T data);

    public void remove(String data);

    public void remove_all();
}
