package kingaidra.decom.gui;

import javax.swing.BoxLayout;
import javax.swing.JPanel;

import ghidra.program.model.address.Address;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.Guess;
import kingaidra.log.Logger;

public class GuessGUI extends JPanel {
    private Guess guess;
    private Logger logger;

    public GuessGUI(Guess guess, Logger logger) {
        this.guess = guess;
        this.logger = logger;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
    }

    public DecomDiff[] run_guess(Address addr) {
        return guess.guess_selected(addr);
    }
}
