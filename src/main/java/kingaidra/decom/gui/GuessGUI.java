package kingaidra.decom.gui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JPanel;

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

        for (Model m : models) {
            JCheckBox cb = new JCheckBox(m.get_name());
            cb.setSelected(guess.get_model_status(m));
            cb.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    JCheckBox src = (JCheckBox) e.getSource();
                    for (Model ml : models) {
                        if (!ml.get_name().equals(src.getText())) {
                            continue;
                        }
                        guess.set_model_status(ml, src.isSelected());
                        break;
                    }
                }
            });
            add(cb);
        }
    }

    public DecomDiff[] run_guess(Address addr) {
        return guess.guess_selected(addr);
    }
}
