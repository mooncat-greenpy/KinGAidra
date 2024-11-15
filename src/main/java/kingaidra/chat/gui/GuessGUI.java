package kingaidra.chat.gui;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

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

import ghidra.program.model.address.Address;
import kingaidra.chat.Guess;
import kingaidra.chat.Conversation;
import kingaidra.log.Logger;

public class GuessGUI extends JPanel {
    Guess guess;

    public GuessGUI(Guess chat) {
        this.guess = chat;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        DefaultTableModel table_model =
                new DefaultTableModel(new Object[] {"ON/OFF", "Name", "Script"}, 0) {
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

                chat.set_model_status(name, status);
                chat.set_model_script(name, script_file);

                table_model.setRowCount(0);
                for (String n : chat.get_models()) {
                    table_model.addRow(
                            new Object[] {chat.get_model_status(n), n, chat.get_model_script(n)});
                }
            }
        });
        for (String n : chat.get_models()) {
            table_model
                    .addRow(new Object[] {chat.get_model_status(n), n, chat.get_model_script(n)});
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
                if (chat.exist_model(name)) {
                    Logger.append_message("Already exists");
                    return;
                }
                if (!name.matches("[a-zA-Z0-9]+")) {
                    Logger.append_message("Only alphanumeric characters");
                    return;
                }
                chat.add_model(name, "none.py");
                table_model.addRow(new Object[] {chat.get_model_status(name), name,
                        chat.get_model_script(name)});
            }
        });
        JButton del_btn = new JButton("Delete Column");
        del_btn.setPreferredSize(button_size);
        del_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int row = table.getSelectedRow();
                if (row == -1) {
                    Logger.append_message("Not selected");
                    return;
                }
                String name = (String) table_model.getValueAt(row, 1);
                chat.remove_model(name);
                table_model.removeRow(row);

                table_model.setRowCount(0);
                for (String n : chat.get_models()) {
                    table_model.addRow(
                            new Object[] {chat.get_model_status(n), n, chat.get_model_script(n)});
                }
            }
        });
        btn_panel.add(add_btn);
        btn_panel.add(del_btn);
        add(btn_panel);
    }

    public Conversation run_guess(String msg, Address addr) {
        return guess.guess(msg, addr);
    }

    public Conversation run_guess(Conversation convo, String msg, Address addr) {
        return guess.guess(convo, msg, addr);
    }
}
