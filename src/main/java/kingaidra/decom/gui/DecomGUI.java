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

import docking.ActionContext;
import docking.Tool;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.action.builder.ActionBuilder;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.Guess;
import kingaidra.decom.Refactor;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerDummy;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelByScript;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.ghidra.RefactorModelPreferences;
import kingaidra.gui.MainProvider;
import kingaidra.log.Logger;
import resources.Icons;
import resources.ResourceManager;

public class DecomGUI extends JPanel {

    private JButton restart_btn;
    private JButton guess_btn;
    private JButton refact_btn;

    private DockingAction conf_action;

    private Program program;
    private PluginTool plugin;
    private KinGAidraChatTaskService srv;
    private GhidraUtil ghidra;
    private GuessGUI ggui;
    private RefactorGUI rgui;

    private boolean busy;

    public DecomGUI(MainProvider provider, Tool dockingTool, Program program, Plugin plugin,
            String owner, KinGAidraChatTaskService srv) {
        super();
        this.program = program;
        this.plugin = plugin.getTool();
        this.srv = srv;
        check_and_set_busy(false);
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        buildPanel();

        setVisible(true);
    }

    private void buildPanel() {
        GhidraPreferences<Model> pref = new RefactorModelPreferences();
        ghidra = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(plugin, program, ghidra, container, srv);
        Guess guess = new Guess(ghidra, ai, pref);
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

        Model test_model = new ModelByScript("Test", "kingaidra_test.py", true);
        Model chatgptlike_chat_model =
                new ModelByScript("ChatGPTLikeChat", "kingaidra_chat_chatgptlike.py", true);
        if (!guess.exist_model(test_model.get_name())) {
            guess.add_model(test_model.get_name(), test_model.get_script());
            guess.set_model_status(test_model.get_name(), test_model.get_active());
        }
        if (!guess.exist_model(chatgptlike_chat_model.get_name())) {
            guess.add_model(chatgptlike_chat_model.get_name(), chatgptlike_chat_model.get_script());
            guess.set_model_status(chatgptlike_chat_model.get_name(), chatgptlike_chat_model.get_active());
        }

        ggui = new GuessGUI(guess);
        rgui = new RefactorGUI(refactor);

        JPanel btn_panel = new JPanel();
        JLabel info_label = new JLabel();
        info_label.setPreferredSize(new Dimension(0, 40));
        add(info_label);
        restart_btn = new JButton("Clean");
        guess_btn = new JButton("Guess");
        refact_btn = new JButton("Refact");
        refact_btn.setEnabled(false);
        Dimension button_size = new Dimension(100, 40);

        restart_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!check_and_set_busy(true)) {
                    Logger.append_message("Another process running");
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
                    Logger.append_message("Another process running");
                    return;
                }
                restart_btn.setEnabled(false);
                guess_btn.setEnabled(false);
                refact_btn.setEnabled(false);
                info_label.setText("Working ...");
                // TODO: Need to be fixed
                Thread th = new Thread(() -> {
                    try {
                        Address addr = ghidra.get_current_addr();
                        if (addr != null) {
                            DecomDiff[] diffs = ggui.run_guess(addr);

                            for (DecomDiff d : diffs) {
                                rgui.add_tab(d.get_model().get_name(), d);
                            }
                        }
                    } finally {
                        info_label.setText("Finished!");
                        restart_btn.setEnabled(true);
                        guess_btn.setEnabled(true);
                        refact_btn.setEnabled(true);
                        check_and_set_busy(false);
                        validate();
                    }
                });
                th.start();

                validate();
            }
        });
        guess_btn.setPreferredSize(button_size);
        btn_panel.add(guess_btn);

        refact_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!check_and_set_busy(true)) {
                    Logger.append_message("Another process running");
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
                        Logger.append_message("Function not found");
                        return;
                    }

                    provider.setVisible(true);
                    provider.toFront();
                    provider.change_tab("Decom");

                    guess_btn.doClick();
                }).popupMenuPath(new String[] {"Refactoring using AI"}).popupMenuGroup("KinGAidra")
                .buildAndInstall(plugin);

        conf_action = new DockingAction("Configure", provider.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                JPanel p = new JPanel();
                if (ggui != null) {
                    p.add(ggui);
                }

                JOptionPane.showMessageDialog(null, p, "Configure", JOptionPane.PLAIN_MESSAGE);
            }
        };

        conf_action.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/decom_conf.png"), null));
        conf_action.setEnabled(true);
        conf_action.markHelpUnnecessary();
        dockingTool.addLocalAction(provider, conf_action);
    }

    synchronized private boolean check_and_set_busy(boolean v) {
        if (v && busy) {
            return false;
        }
        busy = v;
        return true;
    }
}
