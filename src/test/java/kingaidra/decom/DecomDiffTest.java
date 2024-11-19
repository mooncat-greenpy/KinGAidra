package kingaidra.decom;

import org.junit.jupiter.api.Test;

import kingaidra.testutil.ModelDummy;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DecomDiffTest {
    @Test
    void test_constructor() {
        DecomDiff diff = new DecomDiff(null, "old_func", "void func() {}");
        assertEquals(diff.get_addr(), null);
        assertEquals(diff.get_src_code(), "void func() {}");
        assertEquals(diff.get_model(), null);
        assertEquals(diff.get_name().get_id(), 0);
        assertEquals(diff.get_name().get_var_name(), "old_func");
        assertEquals(diff.get_name().get_new_name(), "old_func");
        assertEquals(diff.get_params_len(), 0);
        assertEquals(diff.get_vars_len(), 0);
        assertEquals(diff.get_datatypes_len(), 0);
    }

    @Test
    void test_setter() {
        DecomDiff diff = new DecomDiff(null, "old_func", "void func() {}");

        diff.set_name("new_func");
        assertEquals(diff.get_name().get_id(), 0);
        assertEquals(diff.get_name().get_var_name(), "old_func");
        assertEquals(diff.get_name().get_new_name(), "new_func");

        diff.set_model(new ModelDummy("Test", "test.py", true));
        assertEquals(diff.get_model().get_name(), "Test");

        DiffPair pair1 = new DiffPair(10, "old_param");
        diff.add_param(pair1);
        assertEquals(diff.get_param(10).get_var_name(), "old_param");
        assertEquals(diff.get_params().toArray(new DiffPair[] {})[0].get_var_name(), "old_param");
        assertEquals(diff.get_params_len(), 1);
        diff.set_param_new_name("old_param", "new_param");
        assertEquals(diff.get_param(10).get_new_name(), "new_param");
        diff.delete_param(10);
        assertEquals(diff.get_params_len(), 0);

        DiffPair pair2 = new DiffPair(20, "old_var");
        diff.add_var(pair2);
        assertEquals(diff.get_var(20).get_var_name(), "old_var");
        assertEquals(diff.get_vars().toArray(new DiffPair[] {})[0].get_var_name(), "old_var");
        assertEquals(diff.get_vars_len(), 1);
        diff.set_var_new_name("old_var", "new_var");
        assertEquals(diff.get_var(20).get_new_name(), "new_var");
        diff.delete_var(20);
        assertEquals(diff.get_vars_len(), 0);

        DiffPair pair3 = new DiffPair(30, "old_var");
        diff.add_datatype(pair3);
        assertEquals(diff.get_datatype(30).get_var_name(), "old_var");
        assertEquals(diff.get_datatypes().toArray(new DiffPair[] {})[0].get_var_name(), "old_var");
        assertEquals(diff.get_datatypes_len(), 1);
        diff.set_datatype_new_name("old_var", "new_var");
        assertEquals(diff.get_datatype(30).get_new_name(), "new_var");
        diff.delete_datatype(30);
        assertEquals(diff.get_datatypes_len(), 0);
    }

    @Test
    void test_clone() {
        DecomDiff diff1 = new DecomDiff(null, "old_func", "void func() {}");
        DiffPair pair1 = new DiffPair(10, "old_param");
        diff1.add_param(pair1);
        DiffPair pair2 = new DiffPair(20, "old_var");
        diff1.add_var(pair2);
        DiffPair pair5 = new DiffPair(20, "old_datatype");
        diff1.add_datatype(pair5);
        DecomDiff diff2 = diff1.clone();
        diff2.set_name("new_func");
        assertEquals(diff1.get_name().get_new_name(), "old_func");
        assertEquals(diff2.get_name().get_new_name(), "new_func");

        diff2.set_model(new ModelDummy("Test", "test.py", true));
        assertEquals(diff1.get_model(), null);
        assertEquals(diff2.get_model().get_name(), "Test");

        DiffPair pair3 = new DiffPair(30, "old_param_2");
        diff2.add_param(pair3);
        assertEquals(diff1.get_params_len(), 1);
        assertEquals(diff2.get_params_len(), 2);

        DiffPair pair4 = new DiffPair(40, "old_var_2");
        diff2.add_var(pair4);
        assertEquals(diff1.get_vars_len(), 1);
        assertEquals(diff2.get_vars_len(), 2);

        DiffPair pair6 = new DiffPair(50, "old_datatype_2");
        diff2.add_datatype(pair6);
        assertEquals(diff1.get_datatypes_len(), 1);
        assertEquals(diff2.get_datatypes_len(), 2);
    }
}
