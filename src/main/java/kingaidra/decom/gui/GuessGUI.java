package kingaidra.decom.gui;

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
import kingaidra.decom.DecomDiff;
import kingaidra.decom.Guess;
import kingaidra.decom.ai.Ai;
import kingaidra.decom.ai.Model;
import kingaidra.ghidra.GhidraUtil;

public class GuessGUI extends JPanel {
    Guess guess;

    public GuessGUI(GhidraUtil ghidra, Ai ai, Model[] models) {
        guess = new Guess(ghidra, ai, models);

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

                guess.set_model_status(name, status);
                guess.set_model_script(name, script_file);
            }
        });
        for (String n : guess.get_models()) {
            table_model
                    .addRow(new Object[] {guess.get_model_status(n), n, guess.get_model_script(n)});
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
                if (guess.exist_model(name)) {
                    return;
                }
                guess.add_model(name, "none.py");
                table_model.addRow(new Object[] {guess.get_model_status(name), name,
                        guess.get_model_script(name)});
            }
        });
        JButton del_btn = new JButton("Delete Column");
        del_btn.setPreferredSize(button_size);
        del_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int row = table.getSelectedRow();
                if (row == -1) {
                    return;
                }
                String name = (String) table_model.getValueAt(row, 1);
                guess.remove_model(name);
                table_model.removeRow(row);
            }
        });
        btn_panel.add(add_btn);
        btn_panel.add(del_btn);
        add(btn_panel);
    }

    public DecomDiff[] run_guess(Address addr) {
        return guess.guess_selected(addr);
    }
}
