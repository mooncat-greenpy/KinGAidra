package kingaidra.chat.gui;

import java.awt.BorderLayout;
import java.util.UUID;

import javax.swing.JPanel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.task.TaskMonitor;
import kingaidra.chat.Conversation;
import kingaidra.chat.ConversationContainer;

public class LogGUI extends JPanel {

    ConversationContainer container;
    ChatGUI chat_gui;

    private GhidraTable convo_table;
    private ConversationTableModel convo_table_model;
    private GhidraThreadedTablePanel<Conversation> convo_threaded_table_panel;
    private GhidraTableFilterPanel<Conversation> convo_filter_panel;

    public LogGUI(ConversationContainer container, ChatGUI chat, PluginTool tool, Program program) {
        this.container = container;
        this.chat_gui = chat;

        init_panel(tool, program, TaskMonitor.DUMMY);
        setVisible(true);
    }

    void update(Program new_program) {
        if (convo_table_model == null) {
            return;
        }
        convo_table_model.update_table(new_program);
    }

    private class ConversationTable extends GhidraTable {
        public ConversationTable(ThreadedTableModel<Conversation, ?> model) {
            super(model);
        }
    }

    class ConversationTableModel extends AddressBasedTableModel<Conversation> {

        ConversationTableModel(PluginTool tool, Program program, TaskMonitor monitor) {
            super("Conversation Log", tool, program, monitor, true);
        }

        void update_table(Program new_program) {
            setProgram(new_program);
            reload();
        }

        @Override
        public Address getAddress(int row) {
            Conversation convo = getRowObject(row);
            if (convo.get_addrs().length > 0) {
                return convo.get_addrs()[0];
            }
            return null;
        }

        @Override
        protected void doLoad(Accumulator<Conversation> accumulator, TaskMonitor monitor)
                throws CancelledException {
            UUID[] ids = container.get_ids();
            if (ids == null) {
                return;
            }
            for (UUID id : ids) {
                Conversation convo = container.get_convo(id);
                if (convo == null) {
                    continue;
                }
                accumulator.add(convo);
            }
        }

        @Override
        protected TableColumnDescriptor<Conversation> createTableColumnDescriptor() {
            TableColumnDescriptor<Conversation> descriptor = new TableColumnDescriptor<>();
            descriptor.addVisibleColumn(new ConversationAddressTableColumn());
            descriptor.addVisibleColumn(new ConversationModelNameTableColumn());
            descriptor.addVisibleColumn(new ConversationDataTableColumn());

            return descriptor;
        }

        // ==================================================================================================
        // Inner Classes
        // ==================================================================================================

        private static class ConversationAddressTableColumn
                extends AbstractProgramBasedDynamicTableColumn<Conversation, String> {
            @Override
            public String getColumnName() {
                return "Location";
            }

            @Override
            public String getValue(Conversation rowObject, Settings settings, Program pgm,
                    ServiceProvider serviceProvider) throws IllegalArgumentException {
                String s = "";
                Address[] addrs = rowObject.get_addrs();
                for (Address addr : addrs) {
                    s += String.format("%x ", addr.getOffset());
                }
                return s;
            }

            @Override
            public int getColumnPreferredWidth() {
                return 80;
            }
        }

        private static class ConversationModelNameTableColumn
                extends AbstractProgramBasedDynamicTableColumn<Conversation, String> {
            @Override
            public String getColumnName() {
                return "Model Name";
            }

            @Override
            public String getValue(Conversation rowObject, Settings settings, Program program,
                    ServiceProvider services) throws IllegalArgumentException {
                return rowObject.get_model().get_name();
            }

            @Override
            public int getColumnPreferredWidth() {
                return 100;
            }
        }

        private static class ConversationDataTableColumn
                extends AbstractProgramBasedDynamicTableColumn<Conversation, Conversation> {
            @Override
            public String getColumnName() {
                return "Data";
            }

            @Override
            public Conversation getValue(Conversation rowObject, Settings settings, Program program,
                    ServiceProvider services) throws IllegalArgumentException {
                return rowObject;
            }

            @Override
            public int getColumnPreferredWidth() {
                return 200;
            }
        }
    }

    private void init_panel(PluginTool tool, Program program, TaskMonitor monitor) {
        convo_table_model = new ConversationTableModel(tool, program, monitor);
        convo_threaded_table_panel = new GhidraThreadedTablePanel<>(convo_table_model, 1000) {
            @Override
            protected GTable createTable(ThreadedTableModel<Conversation, ?> model) {
                return new ConversationTable(model);
            }
        };
        convo_table = convo_threaded_table_panel.getTable();
        convo_table.setActionsEnabled(true);
        convo_table.setName("Conversation Log");
        convo_filter_panel = new GhidraTableFilterPanel<>(convo_table, convo_table_model);

        convo_table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                int row_idx = convo_table.getSelectedRow();
                if (row_idx < 0) {
                    return;
                }
                Conversation convo = (Conversation) convo_table.getValueAt(row_idx, 2);
                chat_gui.reset(convo);
            }
        });


        JPanel convo_panel = new JPanel(new BorderLayout());
        convo_panel.add(convo_threaded_table_panel, BorderLayout.CENTER);
        JPanel function_bottom_panel = new JPanel(new BorderLayout());
        function_bottom_panel.add(convo_filter_panel, BorderLayout.CENTER);
        convo_panel.add(function_bottom_panel, BorderLayout.SOUTH);

        add(convo_panel);
        validate();
    }


}
