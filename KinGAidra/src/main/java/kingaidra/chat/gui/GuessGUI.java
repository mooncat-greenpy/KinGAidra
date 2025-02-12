package kingaidra.chat.gui;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.Map;

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
import kingaidra.ai.convo.Conversation;
import kingaidra.chat.Guess;
import kingaidra.log.Logger;

public class GuessGUI extends JPanel {
    private Guess guess;
    private Logger logger;

    public GuessGUI(Guess guess, Logger logger) {
        this.guess = guess;
        this.logger = logger;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
    }

    public Conversation run_guess(String msg, Address addr) {
        return guess.guess(msg, addr);
    }

    public Conversation run_guess(Conversation convo, String msg, Address addr) {
        return guess.guess(convo, msg, addr);
    }

    public List<Map.Entry<String, String>> run_guess_src_code_comments(Address addr) {
        return guess.guess_src_code_comments(addr);
    }
}
