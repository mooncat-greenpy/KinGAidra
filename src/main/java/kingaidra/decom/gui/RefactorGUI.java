package kingaidra.decom.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import ghidra.program.model.address.Address;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.DiffPair;
import kingaidra.decom.Refactor;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.log.Logger;

class DiffTableModel extends DefaultTableModel {
    private DecomDiff diff;

    public DiffTableModel() {
        super(new Object[] {"ON/OFF", "Id", "Type", "Old", "New"}, 0);
    }

    public void add_diff(DecomDiff diff) {
        this.diff = diff;
        addRow(new Object[] {Boolean.TRUE, "-1", "FuncName", diff.get_name().get_old_name(),
                diff.get_name().get_new_name()});
        for (DiffPair pair : diff.get_params()) {
            addRow(new Object[] {Boolean.TRUE, String.format("%d", pair.get_id()), "Param",
                    pair.get_old_name(), pair.get_new_name()});
        }
        for (DiffPair pair : diff.get_vars()) {
            addRow(new Object[] {Boolean.TRUE, String.format("%d", pair.get_id()), "Var",
                    pair.get_old_name(), pair.get_new_name()});
        }
    }

    public DecomDiff get_diff() {
        for (int i = 0; i < getRowCount(); i++) {
            boolean flag = (boolean) getValueAt(i, 0);
            long id = Long.parseLong((String) getValueAt(i, 1));
            String type = (String) getValueAt(i, 2);
            String old_name = (String) getValueAt(i, 3);
            String new_name = (String) getValueAt(i, 4);

            if (type.equals("FuncName")) {
                if (flag) {
                    diff.set_name(new_name);
                } else {
                    diff.set_name(diff.get_name().get_old_name());
                }
            }
            if (type.equals("Param")) {
                if (flag) {
                    diff.set_param_new_name(old_name, new_name);
                } else {
                    diff.delete_param(id);
                }
            }
            if (type.equals("Var")) {
                if (flag) {
                    diff.set_var_new_name(old_name, new_name);
                } else {
                    diff.delete_var(id);
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
    private Refactor refactor;
    private JTabbedPane tabbed_panel;

    public RefactorGUI(GhidraUtil ghidra) {
        refactor = new Refactor(ghidra);

        setLayout(new BorderLayout());

        addr = null;
        name = null;

        info_label = new JLabel();
        info_label.setPreferredSize(new Dimension(0, 40));
        set_info_label();
        add(info_label, BorderLayout.NORTH);

        tabbed_panel = new JTabbedPane();
        add(tabbed_panel, BorderLayout.CENTER);
    }


    public void add_tab(String tab_name, DecomDiff diff) {
        if (addr != null && addr != diff.get_addr()) {
            Logger.append_message("Invalid address function added");
            return;
        }
        if (name != null && name != diff.get_name().get_old_name()) {
            Logger.append_message("Invalid name function added");
            return;
        }
        addr = diff.get_addr();
        name = diff.get_name().get_old_name();
        set_info_label();

        DiffTableModel tableModel = new DiffTableModel();
        tableModel.add_diff(diff);

        JTable table = new JTable(tableModel);
        table.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JCheckBox()));

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
            reset();
            return null;
        }
        JTable t = (JTable) sp.getViewport().getView();
        if (t == null) {
            reset();
            return null;
        }

        DiffTableModel model = (DiffTableModel) t.getModel();
        DecomDiff diff = model.get_diff();

        refactor.refact(diff);

        reset();

        return diff;
    }
}
