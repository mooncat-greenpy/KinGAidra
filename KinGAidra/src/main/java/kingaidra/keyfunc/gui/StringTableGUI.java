package kingaidra.keyfunc.gui;

import java.awt.BorderLayout;
import java.util.Map;

import javax.swing.JPanel;

import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.services.GoToService;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.task.TaskMonitor;

public class StringTableGUI extends JPanel {

    Map.Entry<Function, String>[] func_reason_list;

    private GhidraTable string_table;
    private StringTableModel string_table_model;
    private GhidraThreadedTablePanel<StringDataEntry> string_threaded_table_panel;
    private GhidraTableFilterPanel<StringDataEntry> string_filter_panel;

    public StringTableGUI(PluginTool tool, Program program) {
        func_reason_list = new Map.Entry[]{};
        setLayout(new BorderLayout());
        init_panel(tool, program, TaskMonitor.DUMMY);
        setVisible(true);
    }

    void update(Program new_program, Map.Entry<Function, String>[] new_func_reason_list) {
        if (string_table_model == null) {
            return;
        }
        func_reason_list = new_func_reason_list;
        string_table_model.update_table(new_program);
    }

    private class StringTable extends GhidraTable {
        public StringTable(ThreadedTableModel<StringDataEntry, ?> model) {
            super(model);
        }
    }

    class StringDataEntry {

        private Address addr;
        private String value;
        private Function ref_func;

        StringDataEntry(Address addr, String value, Function ref_func) {
            this.addr = addr;
            this.value = value;
            this.ref_func = ref_func;
        }

        Address get_addr() {
            return addr;
        }

        String get_value() {
            return value;
        }

        Function get_ref_func() {
            return ref_func;
        }
    }

    class StringTableModel extends AddressBasedTableModel<StringDataEntry> {

        StringTableModel(PluginTool tool, Program program, TaskMonitor monitor) {
            super("String Table", tool, program, monitor, true);
        }

        void update_table(Program new_program) {
            setProgram(new_program);
            reload();
        }

        @Override
        public Address getAddress(int row) {
            StringDataEntry row_obj = getRowObject(row);
            return row_obj.get_addr();
        }

        @Override
        protected void doLoad(Accumulator<StringDataEntry> accumulator, TaskMonitor monitor)
                throws CancelledException {
            for (Map.Entry<Function, String> entry : func_reason_list) {
                Function func = entry.getKey();
                accumulator.add(new StringDataEntry(func.getEntryPoint(), entry.getValue(), func));
            }
        }

        @Override
        protected TableColumnDescriptor<StringDataEntry> createTableColumnDescriptor() {
            TableColumnDescriptor<StringDataEntry> descriptor = new TableColumnDescriptor<>();
            descriptor.addVisibleColumn(new StringRefFuncTableColumn());
            descriptor.addVisibleColumn(new StringValueTableColumn());
            descriptor.addVisibleColumn(new StringAddressTableColumn());

            return descriptor;
        }

        // ==================================================================================================
        // Inner Classes
        // ==================================================================================================

        private static class StringRefFuncTableColumn
                extends AbstractProgramBasedDynamicTableColumn<StringDataEntry, String> {
            @Override
            public String getColumnName() {
                return "Function";
            }

            @Override
            public String getValue(StringDataEntry rowObject, Settings settings, Program program,
                    ServiceProvider services) throws IllegalArgumentException {
                Function func = rowObject.get_ref_func();
                if (func != null) {
                    return func.getName();
                }
                return "";
            }

            @Override
            public int getColumnPreferredWidth() {
                return -1;
            }
        }

        private static class StringValueTableColumn
                extends AbstractProgramBasedDynamicTableColumn<StringDataEntry, String> {
            @Override
            public String getColumnName() {
                return "Value";
            }

            @Override
            public String getValue(StringDataEntry rowObject, Settings settings, Program program,
                    ServiceProvider services) throws IllegalArgumentException {
                return rowObject.get_value();
            }

            @Override
            public int getColumnPreferredWidth() {
                return -1;
            }
        }

        private static class StringAddressTableColumn
                extends AbstractProgramBasedDynamicTableColumn<StringDataEntry, Address> {
            @Override
            public String getColumnName() {
                return "Location";
            }

            @Override
            public Address getValue(StringDataEntry rowObject, Settings settings, Program pgm,
                    ServiceProvider serviceProvider) throws IllegalArgumentException {
                Address addr = rowObject.get_addr();
                return addr;
            }

            @Override
            public int getColumnPreferredWidth() {
                return -1;
            }
        }
    }

    private void init_panel(PluginTool tool, Program program, TaskMonitor monitor) {
        string_table_model = new StringTableModel(tool, program, monitor);
        string_threaded_table_panel = new GhidraThreadedTablePanel<>(string_table_model, 0) {
            @Override
            protected GTable createTable(ThreadedTableModel<StringDataEntry, ?> model) {
                return new StringTable(model);
            }
        };
        string_table = string_threaded_table_panel.getTable();
        string_table.setActionsEnabled(true);
        string_table.setName("String Table");
        string_filter_panel = new GhidraTableFilterPanel<>(string_table, string_table_model);
        GoToService go_to_service = tool.getService(GoToService.class);
        string_table.installNavigation(go_to_service, go_to_service.getDefaultNavigatable());

        add(string_threaded_table_panel, BorderLayout.CENTER);
        JPanel function_bottom_panel = new JPanel(new BorderLayout());
        function_bottom_panel.add(string_filter_panel, BorderLayout.CENTER);
        add(function_bottom_panel, BorderLayout.SOUTH);

        validate();
    }
}
