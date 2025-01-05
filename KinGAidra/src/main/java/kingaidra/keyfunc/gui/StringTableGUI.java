package kingaidra.keyfunc.gui;

import java.awt.BorderLayout;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.services.GoToService;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.task.TaskMonitor;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.keyfunc.gui.StringTableGUI.StringDataEntry;

public class StringTableGUI extends JPanel {

    GhidraUtil ghidra;
    Data[] data_list;

    private GhidraTable string_table;
    private StringTableModel string_table_model;
    private GhidraThreadedTablePanel<StringDataEntry> string_threaded_table_panel;
    private GhidraTableFilterPanel<StringDataEntry> string_filter_panel;

    public StringTableGUI(PluginTool tool, Program program, GhidraUtil ghidra) {
        this.ghidra = ghidra;
        data_list = new Data[]{};
        setLayout(new BorderLayout());
        init_panel(tool, program, TaskMonitor.DUMMY);
        setVisible(true);
    }

    void update(Program new_program, Data[] new_data_list, GhidraUtil new_ghidra) {
        if (string_table_model == null) {
            return;
        }
        ghidra = new_ghidra;
        data_list = new_data_list;
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
        private Address ref_addr;
        private Function ref_func;

        StringDataEntry(Address addr, String value, Address ref_addr, Function ref_func) {
            this.addr = addr;
            this.value = value;
            this.ref_addr = ref_addr;
            this.ref_func = ref_func;
        }

        Address get_addr() {
            return addr;
        }

        String get_value() {
            return value;
        }

        Address get_ref_addr() {
            return ref_addr;
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
            Address ref_addr = row_obj.get_ref_addr();
            if (ref_addr == null) {
                return row_obj.get_addr();
            }
            return ref_addr;
        }

        @Override
        protected void doLoad(Accumulator<StringDataEntry> accumulator, TaskMonitor monitor)
                throws CancelledException {
            for (Data data : data_list) {
                Address addr = data.getAddress();
                String value = data.getDefaultValueRepresentation();
                List<Reference> refs = ghidra.get_ref_to(addr);
                if (refs == null || refs.size() == 0) {
                    accumulator.add(new StringDataEntry(addr, value, null, null));
                    continue;
                }
                Set<Address> from_addr_set = new HashSet<>();
                for (Reference ref : refs) {
                    from_addr_set.add(ref.getFromAddress());
                }
                for (Address from_addr : from_addr_set) {
                    Function func = ghidra.get_func(from_addr);
                    accumulator.add(new StringDataEntry(addr, value, from_addr, func));
                }
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
                Address ref_addr = rowObject.get_ref_addr();
                if (func != null) {
                    return func.getName();
                }
                if (ref_addr != null) {
                    return String.format("%x", ref_addr.getOffset());
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

        add(string_threaded_table_panel, BorderLayout.CENTER);
        JPanel function_bottom_panel = new JPanel(new BorderLayout());
        function_bottom_panel.add(string_filter_panel, BorderLayout.CENTER);
        add(function_bottom_panel, BorderLayout.SOUTH);

        validate();
    }
}
