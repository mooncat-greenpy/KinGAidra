package kingaidra.keyfunc.gui;

import javax.swing.BoxLayout;
import javax.swing.JPanel;

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
