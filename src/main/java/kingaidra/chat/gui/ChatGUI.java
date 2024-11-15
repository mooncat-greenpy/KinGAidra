package kingaidra.chat.gui;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;

import docking.ActionContext;
import docking.ComponentProvider;
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
import kingaidra.chat.Conversation;
import kingaidra.chat.Guess;
import kingaidra.chat.KinGAidraChatTaskService;
import kingaidra.chat.ai.Ai;
import kingaidra.chat.ai.Model;
import kingaidra.chat.ai.ModelByScript;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.gui.MainProvider;
import kingaidra.ghidra.ChatModelPreferences;
import kingaidra.log.Logger;
import resources.Icons;

public class ChatGUI extends JPanel {

    private JTextArea input_area;
    private JButton restart_btn;
    private JButton submit_btn;
    private JLabel info_label;
    private JPanel btn_panel;

    private DockingAction conf_action;
    private DockingAction refr_action;

    private Program program;
    private PluginTool plugin;
    private KinGAidraChatTaskService srv;
    private GhidraUtil ghidra;
    private Ai ai;
    private GuessGUI ggui;
    private Conversation cur_convo;

    private boolean busy;

    public ChatGUI(MainProvider provider, Tool dockingTool, Program program, Plugin plugin,
            String owner, KinGAidraChatTaskService srv) {
        super();
        this.program = program;
        this.plugin = plugin.getTool();
        this.srv = srv;
        check_and_set_busy(false);
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        init_panel();

        setVisible(true);
    }

    private void build_panel() {
        removeAll();

        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        Border line_border = new LineBorder(getBackground(), 10, true);
        if (cur_convo != null) {
            for (int i = 0; i < cur_convo.get_msgs_len(); i++) {
                JPanel msg_panel = new JPanel();
                msg_panel.setLayout(new BoxLayout(msg_panel, BoxLayout.X_AXIS));
                msg_panel.setBorder(line_border);

                JTextArea text_area = new JTextArea(cur_convo.get_msg(i));
                text_area.setEditable(false);
                text_area.setLineWrap(true);
                text_area.setWrapStyleWord(true);

                JLabel role_label = new JLabel(cur_convo.get_role(i));
                role_label.setPreferredSize(new Dimension(50, 0));

                if (cur_convo.get_role(i).equals(Conversation.USER_ROLE)) {
                    msg_panel.add(role_label);
                    msg_panel.add(text_area);
                } else {
                    msg_panel.add(text_area);
                    msg_panel.add(role_label);
                }

                p.add(msg_panel);
            }
        }
        input_area.setBorder(line_border);
        p.add(input_area);
        p.add(btn_panel);
        JScrollPane s = new JScrollPane(p);
        s.getVerticalScrollBar().setUnitIncrement(10);

        input_area.setText("");
        input_area.setRows(10);

        add(info_label);
        add(s);
    }

    private void init_panel() {
        GhidraPreferences<Model> pref = new ChatModelPreferences();
        ghidra = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ai = new Ai(plugin, program, srv);
        Guess guess = new Guess(ghidra, ai, pref);

        Model sample_model = new ModelByScript("ChatSample", "kingaidra_chat_sample.py", true);
        Model none_model = new ModelByScript("ChatNone", "kingaidra_chat_none.py", true);
        Model chatgptlike_model =
                new ModelByScript("ChatChatGPTLike", "kingaidra_chat_chatgptlike.py", true);
        if (!guess.exist_model(sample_model.get_name())) {
            guess.add_model(sample_model.get_name(), sample_model.get_script());
            guess.set_model_status(sample_model.get_name(), sample_model.get_active());
        }
        if (!guess.exist_model(none_model.get_name())) {
            guess.add_model(none_model.get_name(), none_model.get_script());
            guess.set_model_status(none_model.get_name(), none_model.get_active());
        }
        if (!guess.exist_model(chatgptlike_model.get_name())) {
            guess.add_model(chatgptlike_model.get_name(), chatgptlike_model.get_script());
            guess.set_model_status(chatgptlike_model.get_name(), chatgptlike_model.get_active());
        }

        ggui = new GuessGUI(guess);

        btn_panel = new JPanel();
        info_label = new JLabel();
        info_label.setPreferredSize(new Dimension(0, 40));
        restart_btn = new JButton("Clean");
        submit_btn = new JButton("Submit");
        Dimension button_size = new Dimension(100, 40);

        restart_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!check_and_set_busy(true)) {
                    Logger.append_message("Another process running");
                    return;
                }
                restart_btn.setEnabled(false);
                submit_btn.setEnabled(false);
                info_label.setText("Working ...");
                try {
                    cur_convo = null;
                    build_panel();
                } finally {
                    info_label.setText("Finished!");
                    restart_btn.setEnabled(true);
                    submit_btn.setEnabled(true);
                    check_and_set_busy(false);
                    validate();
                }
            }
        });
        restart_btn.setPreferredSize(button_size);
        btn_panel.add(restart_btn);

        submit_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!check_and_set_busy(true)) {
                    Logger.append_message("Another process running");
                    return;
                }
                restart_btn.setEnabled(false);
                submit_btn.setEnabled(false);
                info_label.setText("Working ...");
                // TODO: Need to be fixed
                Thread th = new Thread(() -> {
                    try {
                        Address addr = ghidra.get_current_addr();
                        if (addr != null) {
                            if (cur_convo == null) {
                                cur_convo = ggui.run_guess(input_area.getText(), addr);
                            } else {
                                cur_convo = ggui.run_guess(cur_convo, input_area.getText(), addr);
                            }

                            build_panel();
                        }
                    } finally {
                        info_label.setText("Finished!");
                        restart_btn.setEnabled(true);
                        submit_btn.setEnabled(true);
                        check_and_set_busy(false);
                        validate();
                    }
                });
                th.start();

                validate();
            }
        });
        submit_btn.setPreferredSize(button_size);
        btn_panel.add(submit_btn);

        input_area = new JTextArea("");

        build_panel();
    }

    public void initActions(MainProvider provider, Tool dockingTool) {
        new ActionBuilder("Chat with AI", provider.getName())
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
                    provider.change_tab("Chat");

                    input_area.setText("<code>");
                    submit_btn.doClick();
                }).popupMenuPath(new String[] {"Chat using AI"}).popupMenuGroup("KinGAidra")
                .buildAndInstall(plugin);

        conf_action = new DockingAction("ChatConfigure", provider.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                JPanel p = new JPanel();
                if (ggui != null) {
                    p.add(ggui);
                }

                JOptionPane.showMessageDialog(null, p, "ChatConfigure", JOptionPane.PLAIN_MESSAGE);
            }
        };
        conf_action.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, null));
        conf_action.setEnabled(true);
        conf_action.markHelpUnnecessary();
        dockingTool.addLocalAction(provider, conf_action);

        refr_action = new DockingAction("ChatRefresh", provider.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                setVisible(true);
            }
        };
        refr_action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
        refr_action.setEnabled(true);
        refr_action.markHelpUnnecessary();
        dockingTool.addLocalAction(provider, refr_action);
    }

    synchronized private boolean check_and_set_busy(boolean v) {
        if (v && busy) {
            return false;
        }
        busy = v;
        return true;
    }
}
