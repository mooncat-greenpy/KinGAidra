package kingaidra.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.swing.BoxLayout;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;

import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelConf;
import kingaidra.log.Logger;

public class ModelConfGUI extends JPanel {
    private static int NAME_COLUMN_IDX = 0;
    private static int SCRIPT_COLUMN_IDX = 1;
    private static int ONOFF_COLUMN_BASE_IDX = 2;

    private List<ModelConf> model_conf_list;
    private Logger logger;

    public ModelConfGUI(List<ModelConf> model_conf_list, Logger logger) {
        this.model_conf_list = model_conf_list;
        this.logger = logger;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        List<Object> column_names = new LinkedList<>();
        column_names.add("Name");
        column_names.add("Script");
        for (ModelConf model_conf : model_conf_list) {
            column_names.add(model_conf.get_name());
        }
        DefaultTableModel table_model =
                new DefaultTableModel(column_names.toArray(), 0) {
                    @Override
                    public boolean isCellEditable(int row, int column) {
                        return column != NAME_COLUMN_IDX;
                    }

                    @Override
                    public Class<?> getColumnClass(int columnIndex) {
                        return (columnIndex != NAME_COLUMN_IDX && columnIndex != SCRIPT_COLUMN_IDX) ?
                                Boolean.class : super.getColumnClass(columnIndex);
                    }
                };
        table_model.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                if (e.getType() != TableModelEvent.UPDATE) {
                    return;
                }
                int row = e.getFirstRow();

                String name = (String) table_model.getValueAt(row, NAME_COLUMN_IDX);
                String script_file = (String) table_model.getValueAt(row, SCRIPT_COLUMN_IDX);

                for (int i = 0; i < model_conf_list.size(); i++) {
                    ModelConf model_conf = model_conf_list.get(i);
                    boolean status = (boolean) table_model.getValueAt(row, ONOFF_COLUMN_BASE_IDX + i);
                    model_conf.set_model_status(name, status);
                    model_conf.set_model_script(name, script_file);
                }

                reflesh_rows(table_model);
            }
        });
        reflesh_rows(table_model);

        JTable table = new JTable(table_model);
        for (int i = 0; i < model_conf_list.size(); i++) {
            table.getColumnModel().getColumn(ONOFF_COLUMN_BASE_IDX + i)
                    .setCellEditor(new DefaultCellEditor(new JCheckBox()));
        }

        add(new JScrollPane(table));

        JPanel btn_panel = new JPanel();
        Dimension button_size = new Dimension(140, 30);

        JButton add_btn = new JButton("Add Column");
        add_btn.setPreferredSize(button_size);
        add_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JLabel name_label = new JLabel("name: ");
                JTextField name_field = new JTextField(20);
                JLabel script_label = new JLabel("script: ");
                JTextField script_field = new JTextField(20);

                JPanel name_panel = new JPanel();
                name_panel.add(name_label, BorderLayout.WEST);
                name_panel.add(name_field, BorderLayout.CENTER);
                JPanel script_panel = new JPanel();
                script_panel.add(script_label, BorderLayout.WEST);
                script_panel.add(script_field, BorderLayout.CENTER);

                JPanel input_panel = new JPanel(new GridLayout(2, 1));
                input_panel.add(name_panel);
                input_panel.add(script_panel);

                int option = JOptionPane.showConfirmDialog(null, input_panel, "What is the Model name and script?", JOptionPane.OK_CANCEL_OPTION);
                if (option == JOptionPane.CANCEL_OPTION) {
                    logger.append_message("Canceled");
                    return;
                }

                String name = name_field.getText();
                String script = script_field.getText();
                if (!name.matches("[a-zA-Z0-9_\\-]+")) {
                    logger.append_message("Only alphanumeric characters, underscores, and hyphens are allowed");
                    return;
                }
                for (ModelConf model_conf : model_conf_list) {
                    if (model_conf.exist_model(name)) {
                        continue;
                    }
                    model_conf.add_model(name, script);
                }

                reflesh_rows(table_model);
            }
        });
        JButton del_btn = new JButton("Delete Column");
        del_btn.setPreferredSize(button_size);
        del_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int row = table.getSelectedRow();
                if (row == -1) {
                    logger.append_message("Not selected");
                    return;
                }
                String name = (String) table_model.getValueAt(row, NAME_COLUMN_IDX);
                for (ModelConf model_conf : model_conf_list) {
                    model_conf.remove_model(name);
                }
                table_model.removeRow(row);

                reflesh_rows(table_model);
            }
        });
        btn_panel.add(add_btn);
        btn_panel.add(del_btn);
        add(btn_panel);
    }

    private void reflesh_rows(DefaultTableModel table_model) {
        List<Model> tmp_model_list = new LinkedList<>();
        for (ModelConf model_conf : model_conf_list) {
            for (String name : model_conf.get_models()) {
                tmp_model_list.add(model_conf.get_model(name));
            }
        }
        List<Model> model_list = new LinkedList<>();
        for (Model model : tmp_model_list) {
            if (Arrays.stream(model_list.toArray(new Model[]{})).anyMatch(p ->
                    p.get_name().equals(model.get_name()) &&
                    p.get_script().equals(model.get_script()))) {
                continue;
            }
            model_list.add(model);
        }

        table_model.setRowCount(0);
        for (Model m : model_list) {
            List<Object> values = new LinkedList<>();
            values.add(m.get_name());
            values.add(m.get_script());
            for (ModelConf model_conf : model_conf_list) {
                if (!model_conf.exist_model(m.get_name())) {
                    model_conf.add_model(m.get_name(), m.get_script());
                }

                values.add(model_conf.get_model_status(m.get_name()));
            }
            table_model.addRow(values.toArray());
        }
    }
}
