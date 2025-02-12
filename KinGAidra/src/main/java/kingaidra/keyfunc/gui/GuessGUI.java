package kingaidra.keyfunc.gui;

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

import kingaidra.keyfunc.Guess;
import kingaidra.log.Logger;

import ghidra.program.model.listing.Function;

public class GuessGUI extends JPanel {
    private Guess guess;
    private Logger logger;

    public GuessGUI(Guess guess, Logger logger) {
        this.guess = guess;
        this.logger = logger;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
    }

    public Function[] run_guess(String call_tree) {
        return guess.guess(call_tree, null);
    }
}
