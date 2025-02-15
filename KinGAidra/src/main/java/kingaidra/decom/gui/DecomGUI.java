package kingaidra.decom.gui;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.function.Function;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.Tool;
import docking.action.builder.ActionBuilder;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.Guess;
import kingaidra.decom.Refactor;
import kingaidra.ai.Ai;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelByScript;
import kingaidra.ai.model.ModelConf;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.gui.MainProvider;
import kingaidra.log.Logger;

public class DecomGUI extends JPanel {

    private JButton restart_btn;
    private JButton guess_btn;
    private JButton refact_btn;

    private Program program;
    private PluginTool plugin;
    private KinGAidraChatTaskService srv;
    private GhidraUtil ghidra;
    private ModelConf conf;
    private Ai ai;
    private Logger logger;
    private GuessGUI ggui;
    private RefactorGUI rgui;

    private boolean busy;

    public DecomGUI(MainProvider provider, Tool dockingTool, Program program, Plugin plugin,
            String owner, KinGAidraChatTaskService srv, GhidraUtil ghidra, ModelConf conf, Ai ai, Logger logger) {
        super();
        this.program = program;
        this.plugin = plugin.getTool();
        this.srv = srv;
        this.ghidra = ghidra;
        this.conf = conf;
        this.ai = ai;
        this.logger = logger;
        check_and_set_busy(false);
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        buildPanel();

        setVisible(true);
    }

    private void buildPanel() {
        Guess guess = new Guess(ghidra, ai, conf);
        Refactor refactor = new Refactor(ghidra, ai, new Function<String, String>() {
            @Override
            public String apply(String msg) {
                JTextArea text = new JTextArea(30, 100);
                text.setText(msg);
                JScrollPane scroll = new JScrollPane(text);
                int option = JOptionPane.showConfirmDialog(null, scroll, "Fix!", JOptionPane.OK_CANCEL_OPTION);
                if (option == JOptionPane.CANCEL_OPTION) {
                    return null;
                }
                return text.getText();
            }
        });

        Model chatgptlike_chat_model =
                new ModelByScript("ChatGPTLike", "kingaidra_chat.py", true);
        if (!guess.get_model_conf().exist_model(chatgptlike_chat_model.get_name())) {
            guess.get_model_conf().add_model(chatgptlike_chat_model.get_name(), chatgptlike_chat_model.get_script());
            guess.get_model_conf().set_model_status(chatgptlike_chat_model.get_name(), chatgptlike_chat_model.get_active());
        }

        ggui = new GuessGUI(guess, logger);
        rgui = new RefactorGUI(refactor, logger);

        JPanel btn_panel = new JPanel();
        JLabel info_label = new JLabel();
        info_label.setPreferredSize(new Dimension(0, 40));
        add(info_label);
        restart_btn = new JButton("Clean");
        guess_btn = new JButton("Guess");
        refact_btn = new JButton("Refactor");
        refact_btn.setEnabled(false);
        Dimension button_size = new Dimension(100, 40);

        restart_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!check_and_set_busy(true)) {
                    logger.append_message("Another process running");
                    return;
                }
                restart_btn.setEnabled(false);
                guess_btn.setEnabled(false);
                refact_btn.setEnabled(false);
                info_label.setText("Working ...");
                try {
                    rgui.reset();
                } finally {
                    info_label.setText("Finished!");
                    restart_btn.setEnabled(true);
                    guess_btn.setEnabled(true);
                    refact_btn.setEnabled(false);
                    check_and_set_busy(false);
                    validate();
                }
            }
        });
        restart_btn.setPreferredSize(button_size);
        btn_panel.add(restart_btn);

        guess_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!check_and_set_busy(true)) {
                    logger.append_message("Another process running");
                    return;
                }
                restart_btn.setEnabled(false);
                guess_btn.setEnabled(false);
                refact_btn.setEnabled(false);
                info_label.setText("Working ...");
                // TODO: Need to be fixed
                Thread th = new Thread(() -> {
                    Address addr = null;
                    DecomDiff[] diffs = null;
                    try {
                        addr = ghidra.get_current_addr();
                        if (addr != null) {
                            diffs = ggui.run_guess(addr);

                            for (DecomDiff d : diffs) {
                                rgui.add_tab(d.get_model().get_name(), d);
                            }
                        }
                    } finally {
                        if (diffs == null || diffs.length == 0) {
                            info_label.setText("Failed!");
                            restart_btn.setEnabled(true);
                            guess_btn.setEnabled(true);
                            refact_btn.setEnabled(false);
                        } else {
                            info_label.setText("Finished!");
                            restart_btn.setEnabled(true);
                            guess_btn.setEnabled(true);
                            refact_btn.setEnabled(true);
                        }
                        check_and_set_busy(false);
                        validate();
                    }
                });
                th.start();

                validate();
            }
        });
        guess_btn.setPreferredSize(button_size);
        guess_btn.setToolTipText("Get refactoring ideas");
        btn_panel.add(guess_btn);

        refact_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!check_and_set_busy(true)) {
                    logger.append_message("Another process running");
                    return;
                }
                restart_btn.setEnabled(false);
                guess_btn.setEnabled(false);
                refact_btn.setEnabled(false);
                info_label.setText("Working ...");
                try {
                    rgui.run_refact();
                } finally {
                    info_label.setText("Finished!");
                    restart_btn.setEnabled(true);
                    guess_btn.setEnabled(true);
                    refact_btn.setEnabled(false);
                    check_and_set_busy(false);
                    validate();
                }
            }
        });
        refact_btn.setPreferredSize(button_size);
        refact_btn.setToolTipText("Refactor decompile results with information from selected tabs");
        btn_panel.add(refact_btn);

        add(btn_panel);
        add(rgui);
    }

    public void initActions(MainProvider provider, Tool dockingTool) {
        new ActionBuilder("Refactoring using AI", provider.getName())
                .withContext(ProgramLocationActionContext.class).enabledWhen(context -> {
                    var func = context.getProgram().getFunctionManager()
                            .getFunctionContaining(context.getAddress());
                    return func != null;
                }).onAction(context -> {
                    var func = context.getProgram().getFunctionManager()
                            .getFunctionContaining(context.getAddress());
                    if (func == null) {
                        logger.append_message("Function not found");
                        return;
                    }

                    provider.setVisible(true);
                    provider.toFront();
                    provider.change_tab("Decom");

                    guess_btn.doClick();
                }).popupMenuPath(new String[] {"Refactoring using AI"}).popupMenuGroup("KinGAidra")
                .buildAndInstall(plugin);
    }

    synchronized private boolean check_and_set_busy(boolean v) {
        if (v && busy) {
            return false;
        }
        busy = v;
        return true;
    }
}
