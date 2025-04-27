package kingaidra.decom.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import ghidra.program.model.address.Address;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.DiffPair;
import kingaidra.decom.Refactor;
import kingaidra.log.Logger;

class DiffTableModel extends DefaultTableModel {
    private DecomDiff diff;

    public DiffTableModel() {
        super(new Object[] {"ON/OFF", "Id", "Type", "Old", "New", "DataType"}, 0);
    }

    public void add_diff(DecomDiff d) {
        this.diff = d;
        addRow(new Object[] {Boolean.TRUE, "-1", "FuncName", diff.get_name().get_var_name(),
                diff.get_name().get_new_name(), ""});
        for (DiffPair pair : diff.get_params()) {
            addRow(new Object[] {Boolean.TRUE, String.format("%d", pair.get_id()), "Param",
                    pair.get_var_name(), pair.get_new_name(),
                    diff.get_datatype(pair.get_id()).get_new_name()});
        }
        for (DiffPair pair : diff.get_vars()) {
            addRow(new Object[] {Boolean.TRUE, String.format("%d", pair.get_id()), "Var",
                    pair.get_var_name(), pair.get_new_name(),
                    diff.get_datatype(pair.get_id()).get_new_name()});
        }
    }

    public DecomDiff get_diff(boolean rename, boolean retype) {
        for (int i = 0; i < getRowCount(); i++) {
            boolean flag = (boolean) getValueAt(i, 0);
            long id = Long.parseLong((String) getValueAt(i, 1));
            String type = (String) getValueAt(i, 2);
            String var_name = (String) getValueAt(i, 3);
            String new_name = (String) getValueAt(i, 4);
            String dt_name = (String) getValueAt(i, 5);

            if (type.equals("FuncName")) {
                if (flag) {
                    diff.set_name(new_name);
                } else {
                    diff.set_name(diff.get_name().get_var_name());
                }
            }
            if (type.equals("Param")) {
                if (flag && rename) {
                    diff.set_param_new_name(var_name, new_name);
                } else {
                    diff.delete_param(id);
                }
                if (flag && retype) {
                    diff.set_datatype_new_name(var_name, dt_name);
                } else {
                    diff.delete_datatype(id);
                }
            }
            if (type.equals("Var")) {
                if (flag && rename) {
                    diff.set_var_new_name(var_name, new_name);
                } else {
                    diff.delete_var(id);
                }
                if (flag && retype) {
                    diff.set_datatype_new_name(var_name, dt_name);
                } else {
                    diff.delete_datatype(id);
                }
            }
        }
        return diff;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return column != 1 && column != 2 && column != 3;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return columnIndex == 0 ? Boolean.class : super.getColumnClass(columnIndex);
    }
}


public class RefactorGUI extends JPanel {
    private Address addr;
    private String name;

    private JLabel info_label;
    private JCheckBox rename_chkbox;
    private JCheckBox retype_chkbox;
    private JCheckBox datatype_chkbox;
    private Refactor refactor;
    private JTabbedPane tabbed_panel;

    private Logger logger;

    public RefactorGUI(Refactor refactor, Logger logger) {
        this.refactor = refactor;
        this.logger = logger;

        setLayout(new BorderLayout());

        addr = null;
        name = null;

        info_label = new JLabel();
        info_label.setPreferredSize(new Dimension(0, 40));
        set_info_label();
        rename_chkbox = new JCheckBox("Rename");
        rename_chkbox.setSelected(true);
        retype_chkbox = new JCheckBox("Retype");
        retype_chkbox.setSelected(false);
        retype_chkbox.setToolTipText("Enabling this option may cause some variable operations to fail.");
        datatype_chkbox = new JCheckBox("Resolve datatype");
        datatype_chkbox.setSelected(false);
        datatype_chkbox.setToolTipText("Enabling this option may result in incorrect data types being added.");
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.add(info_label);
        panel.add(rename_chkbox);
        panel.add(retype_chkbox);
        // A lot of noise
        panel.add(datatype_chkbox);

        tabbed_panel = new JTabbedPane();
        add(panel, BorderLayout.NORTH);
        add(tabbed_panel, BorderLayout.CENTER);
    }


    public void add_tab(String tab_name, DecomDiff diff) {
        if (addr != null && addr != diff.get_addr()) {
            logger.append_message("Invalid address function added");
            return;
        }
        if (name != null && name != diff.get_name().get_var_name()) {
            logger.append_message("Invalid name function added");
            return;
        }
        addr = diff.get_addr();
        name = diff.get_name().get_var_name();
        rename_chkbox.setSelected(true);
        retype_chkbox.setSelected(false);
        datatype_chkbox.setSelected(false);
        set_info_label();

        DiffTableModel tableModel = new DiffTableModel();
        tableModel.add_diff(diff);

        JTable table = new JTable(tableModel);
        table.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JCheckBox()));
        table.getColumnModel().getColumn(1).setMinWidth(0);
        table.getColumnModel().getColumn(1).setMaxWidth(0);

        tabbed_panel.add(tab_name, new JScrollPane(table));

        validate();
    }

    private void set_info_label() {
        String a, n;
        if (addr == null) {
            a = "null";
        } else {
            a = String.format("%x", addr.getOffset());
        }
        if (name == null) {
            n = "null";
        } else {
            n = String.format("%s", name);
        }
        info_label.setText(String.format("%s (%s)", n, a));
    }

    public void reset() {
        tabbed_panel.removeAll();
        addr = null;
        name = null;
        set_info_label();
    }

    public DecomDiff run_refact() {
        JScrollPane sp = (JScrollPane) tabbed_panel.getSelectedComponent();
        if (sp == null) {
            logger.append_message("Not selected");
            reset();
            return null;
        }
        JTable t = (JTable) sp.getViewport().getView();
        if (t == null) {
            logger.append_message("Failed to get table");
            reset();
            return null;
        }

        DiffTableModel model = (DiffTableModel) t.getModel();
        DecomDiff diff = model.get_diff(rename_chkbox.isSelected(), retype_chkbox.isSelected());

        try {
            refactor.refact(diff, datatype_chkbox.isSelected());
        } finally {
            reset();
        }

        return diff;
    }
}
