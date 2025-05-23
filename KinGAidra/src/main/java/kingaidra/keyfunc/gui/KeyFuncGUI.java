package kingaidra.keyfunc.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;

import docking.Tool;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import kingaidra.ai.Ai;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelByScript;
import kingaidra.ai.model.ModelConf;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.keyfunc.Guess;
import kingaidra.log.Logger;
import kingaidra.ghidra.ChatModelPreferences;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.gui.MainProvider;

public class KeyFuncGUI extends JPanel {

    private Program program;
    private PluginTool plugin;
    private KinGAidraChatTaskService srv;
    private GhidraUtil ghidra;
    private ModelConf conf;
    private Ai ai;
    private Logger logger;

    private JButton guess_btn;
    private GuessGUI ggui;
    private StringTableGUI string_table;

    private boolean busy;

    public KeyFuncGUI(MainProvider provider, Tool dockingTool, Program program, Plugin plugin,
            String owner, KinGAidraChatTaskService srv, GhidraUtil ghidra, ModelConf conf, Ai ai, Logger logger) {
        super();
        this.program = program;
        this.plugin = plugin.getTool();
        this.srv = srv;
        this.ghidra = ghidra;
        this.conf = conf;
        this.ai = ai;
        this.logger = logger;
        setLayout(new BorderLayout());

        init_panel();

        setVisible(true);
    }

    private void init_panel() {
        GhidraPreferences<Model> old_pref = new ChatModelPreferences("keyfunc");
        old_pref.remove_all();
        Guess guess = new Guess(ghidra, ai, conf);

        Model chatgptlike_model =
                new ModelByScript("ChatGPTLike", "kingaidra_chat.py", true);
        if (!guess.get_model_conf().exist_model(chatgptlike_model.get_name())) {
            guess.get_model_conf().add_model(chatgptlike_model.get_name(), chatgptlike_model.get_script());
            guess.get_model_conf().set_model_status(chatgptlike_model.get_name(), chatgptlike_model.get_active());
        }

        ggui = new GuessGUI(guess, logger);

        guess_btn = new JButton("Guess");
        Dimension button_size = new Dimension(100, 30);
        guess_btn.setPreferredSize(button_size);
        guess_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!check_and_set_busy(true)) {
                    return;
                }
                logger.append_message("Start: KeyFunc");
                guess_btn.setEnabled(false);
                Thread th = new Thread(() -> {
                    try {
                        Data[] data = guess.guess_string_data();
                        string_table.update(program, data, ghidra);
                    } finally {
                        guess_btn.setEnabled(true);

                        check_and_set_busy(false);
                        logger.append_message("Finish: KeyFunc");
                        validate();
                    }
                });
                th.start();

                validate();
            }
        });

        JPanel input_panel = new JPanel();
		input_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        input_panel.add(guess_btn);
        add(input_panel, BorderLayout.NORTH);
        string_table = new StringTableGUI(plugin, program, ghidra);
        add(string_table, BorderLayout.CENTER);
    }

    synchronized private boolean check_and_set_busy(boolean v) {
        if (v && busy) {
            return false;
        }
        busy = v;
        return true;
    }

    public void initActions(MainProvider provider, Tool dockingTool) {
    }
}
