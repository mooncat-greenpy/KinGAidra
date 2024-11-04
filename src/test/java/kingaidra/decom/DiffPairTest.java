package kingaidra.decom;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DiffPairTest {
    @Test
    void test_constructor() {
        DiffPair pair1 = new DiffPair(10, "old_func");
        assertEquals(pair1.get_id(), 10);
        assertEquals(pair1.get_old_name(), "old_func");
        assertEquals(pair1.get_new_name(), pair1.get_old_name());
    }

    @Test
    void test_set_name() {
        DiffPair pair1 = new DiffPair(10, "old_func");
        assertEquals(pair1.get_id(), 10);
        assertEquals(pair1.get_old_name(), "old_func");
        assertEquals(pair1.get_new_name(), pair1.get_old_name());
        pair1.set_new_name("new_func");
        assertEquals(pair1.get_id(), 10);
        assertEquals(pair1.get_old_name(), "old_func");
        assertEquals(pair1.get_new_name(), "new_func");
    }

    @Test
    void test_clone() {
        DiffPair pair1 = new DiffPair(10, "old_func");
        DiffPair pair2 = pair1.clone();
        assertEquals(pair1.get_id(), 10);
        assertEquals(pair1.get_old_name(), "old_func");
        assertEquals(pair1.get_new_name(), "old_func");
        assertEquals(pair2.get_id(), 10);
        assertEquals(pair2.get_old_name(), "old_func");
        assertEquals(pair2.get_new_name(), "old_func");
        pair2.set_new_name("new_func");
        assertEquals(pair1.get_id(), 10);
        assertEquals(pair1.get_old_name(), "old_func");
        assertEquals(pair1.get_new_name(), "old_func");
        assertEquals(pair2.get_id(), 10);
        assertEquals(pair2.get_old_name(), "old_func");
        assertEquals(pair2.get_new_name(), "new_func");
    }
}
