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
import kingaidra.chat.Chat;
import kingaidra.chat.KinGAidraChatTaskService;
import kingaidra.chat.ai.Ai;
import kingaidra.chat.ai.Model;
import kingaidra.chat.ai.ModelByScript;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.ghidra.ChatModelPreferences;
import kingaidra.log.Logger;
import resources.Icons;

public class ChatGUI extends JPanel {

    private JTextArea input_area;
    private JButton restart_btn;
    private JButton submit_btn;

    private DockingAction conf_action;
    private DockingAction refr_action;

    private Program program;
    private PluginTool plugin;
    private KinGAidraChatTaskService srv;
    private GhidraUtil ghidra;
    private Ai ai;
    private GuessGUI ggui;

    private boolean busy;

    public ChatGUI(ComponentProvider provider, Tool dockingTool, Program program, Plugin plugin,
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
        GhidraPreferences<Model> pref = new ChatModelPreferences();
        ghidra = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ai = new Ai(plugin, program, srv);
        Chat chat = new Chat(ghidra, ai, pref);

        Model sample_model = new ModelByScript("ChatSample", "kingaidra_chat_sample.py", true);
        Model none_model = new ModelByScript("ChatNone", "kingaidra_chat_none.py", true);
        Model chatgptlike_model =
                new ModelByScript("ChatChatGPTLike", "kingaidra_chat_chatgptlike.py", true);
        if (!chat.exist_model(sample_model.get_name())) {
            chat.add_model(sample_model.get_name(), sample_model.get_script());
            chat.set_model_status(sample_model.get_name(), sample_model.get_active());
        }
        if (!chat.exist_model(none_model.get_name())) {
            chat.add_model(none_model.get_name(), none_model.get_script());
            chat.set_model_status(none_model.get_name(), none_model.get_active());
        }
        if (!chat.exist_model(chatgptlike_model.get_name())) {
            chat.add_model(chatgptlike_model.get_name(), chatgptlike_model.get_script());
            chat.set_model_status(chatgptlike_model.get_name(), chatgptlike_model.get_active());
        }

        ggui = new GuessGUI(chat);

        JPanel btn_panel = new JPanel();
        JLabel info_label = new JLabel();
        info_label.setPreferredSize(new Dimension(0, 40));
        add(info_label);
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
                    input_area.setText("");
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
                            Conversation convo = ggui.run_guess(input_area.getText(), addr);
                            input_area.setText(convo.get_msg(1));
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
        add(new JScrollPane(input_area));
        add(btn_panel);
    }

    public void initActions(ComponentProvider provider, Tool dockingTool) {
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
