package kingaidra.gui;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedList;
import java.util.List;

import javax.swing.BoxLayout;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;

import kingaidra.ai.model.ModelConf;
import kingaidra.log.Logger;

public class ModelConfGUI extends JPanel {
    private ModelConf model_conf;
    private Logger logger;

    public ModelConfGUI(ModelConf model_conf, Logger logger) {
        this.model_conf = model_conf;
        this.logger = logger;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        List<Object> column_names = new LinkedList<>();
        column_names.add("ON/OFF");
        column_names.add("Name");
        column_names.add("Script");
        DefaultTableModel table_model =
                new DefaultTableModel(column_names.toArray(), 0) {
                    @Override
                    public boolean isCellEditable(int row, int column) {
                        return column != 1;
                    }

                    @Override
                    public Class<?> getColumnClass(int columnIndex) {
                        return columnIndex == 0 ? Boolean.class : super.getColumnClass(columnIndex);
                    }
                };
        table_model.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                if (e.getType() != TableModelEvent.UPDATE) {
                    return;
                }
                int row = e.getFirstRow();

                boolean status = (boolean) table_model.getValueAt(row, 0);
                String name = (String) table_model.getValueAt(row, 1);
                String script_file = (String) table_model.getValueAt(row, 2);

                model_conf.set_model_status(name, status);
                model_conf.set_model_script(name, script_file);

                table_model.setRowCount(0);
                for (String n : model_conf.get_models()) {
                    List<Object> values = new LinkedList<>();
                    values.add(model_conf.get_model_status(n));
                    values.add(n);
                    values.add(model_conf.get_model_script(n));
                    table_model.addRow(values.toArray());
                }
            }
        });
        for (String n : model_conf.get_models()) {
            List<Object> values = new LinkedList<>();
            values.add(model_conf.get_model_status(n));
            values.add(n);
            values.add(model_conf.get_model_script(n));
            table_model.addRow(values.toArray());
        }

        JTable table = new JTable(table_model);
        table.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JCheckBox()));
        add(new JScrollPane(table));

        JPanel btn_panel = new JPanel();
        Dimension button_size = new Dimension(140, 30);

        JButton add_btn = new JButton("Add Column");
        add_btn.setPreferredSize(button_size);
        add_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String name = JOptionPane.showInputDialog(null, "What is the Model name?");
                if (name == null) {
                    logger.append_message("Canceled");
                    return;
                }
                if (model_conf.exist_model(name)) {
                    logger.append_message("Already exists");
                    return;
                }
                if (!name.matches("[a-zA-Z0-9]+")) {
                    logger.append_message("Only alphanumeric characters");
                    return;
                }
                model_conf.add_model(name, "none.py");
                table_model.addRow(new Object[] {model_conf.get_model_status(name), name,
                        model_conf.get_model_script(name)});
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
                String name = (String) table_model.getValueAt(row, 1);
                model_conf.remove_model(name);
                table_model.removeRow(row);

                table_model.setRowCount(0);
                for (String n : model_conf.get_models()) {
                    List<Object> values = new LinkedList<>();
                    values.add(model_conf.get_model_status(n));
                    values.add(n);
                    values.add(model_conf.get_model_script(n));
                    table_model.addRow(values.toArray());
                }
            }
        });
        btn_panel.add(add_btn);
        btn_panel.add(del_btn);
        add(btn_panel);
    }
}
