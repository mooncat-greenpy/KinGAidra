package kingaidra.decom.gui;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BoxLayout;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JCheckBox;
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
                int column = e.getColumn();
                if (column != 0) {
                    return;
                }

                boolean status = (boolean) table_model.getValueAt(row, 0);
                String name = (String) table_model.getValueAt(row, 1);
                for (Model ml : models) {
                    if (!ml.get_name().equals(name)) {
                        continue;
                    }
                    guess.set_model_status(ml, status);
                    break;
                }
            }
        });
        for (Model m : models) {
            table_model
                    .addRow(new Object[] {guess.get_model_status(m), m.get_name(), m.get_script()});
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
                table_model.addRow(new Object[] {Boolean.FALSE, "", ""});
            }
        });
        JButton del_btn = new JButton("Delete Column");
        del_btn.setPreferredSize(button_size);
        del_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int row_idx = table.getSelectedRow();
                if (row_idx == -1) {
                    return;
                }
                table_model.removeRow(row_idx);
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
