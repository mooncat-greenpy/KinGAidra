package kingaidra.chat.gui;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JEditorPane;
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
import kingaidra.chat.ConversationContainer;
import kingaidra.chat.ConversationContainerDummy;
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

import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.data.MutableDataSet;
import com.vladsch.flexmark.html.HtmlRenderer;

public class ChatGUI extends JPanel {

    private JTextArea input_area;
    private JButton restart_btn;
    private JButton submit_btn;
    private JLabel info_label;
    private JPanel btn_panel;

    private DockingAction conf_action;
    private DockingAction log_action;

    private Program program;
    private PluginTool plugin;
    private KinGAidraChatTaskService srv;
    private GhidraUtil ghidra;
    private Ai ai;
    private ConversationContainer container;
    private GuessGUI ggui;
    private LogGUI lgui;
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

    private String convert_md_to_html(String markdown) {
        MutableDataSet options = new MutableDataSet();
        Parser parser = Parser.builder(options).build();
        HtmlRenderer renderer = HtmlRenderer.builder(options).build();

        return renderer.render(parser.parse(markdown));
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

                String html = convert_md_to_html(cur_convo.get_msg(i));
                JEditorPane edit_panel = new JEditorPane();
                edit_panel.setContentType("text/html");
                edit_panel.setText(html);
                edit_panel.setEditable(false);

                JLabel role_label = new JLabel(cur_convo.get_role(i));
                role_label.setPreferredSize(new Dimension(50, 0));

                if (cur_convo.get_role(i).equals(Conversation.USER_ROLE)) {
                    msg_panel.add(role_label);
                    msg_panel.add(edit_panel);
                } else {
                    msg_panel.add(edit_panel);
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
        container = new ConversationContainerDummy();
        lgui = new LogGUI(container, this, plugin, program);

        btn_panel = new JPanel();
        info_label = new JLabel();
        info_label.setPreferredSize(new Dimension(0, 40));
        restart_btn = new JButton("Clean");
        submit_btn = new JButton("Submit");
        Dimension button_size = new Dimension(100, 40);

        restart_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                reset(null);
            }
        });
        restart_btn.setPreferredSize(button_size);
        btn_panel.add(restart_btn);

        submit_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                guess(ghidra.get_current_addr());
            }
        });
        submit_btn.setPreferredSize(button_size);
        btn_panel.add(submit_btn);

        input_area = new JTextArea("");
        input_area.setLineWrap(true);
        input_area.setWrapStyleWord(true);

        build_panel();
    }

    public void initActions(MainProvider provider, Tool dockingTool) {
        new ActionBuilder("Explain with AI", provider.getName())
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

                    reset(null);
                    input_area.setText(
                            "Please explain what the following decompiled C function does. "
                                    + "Break down its logic, and describe the purpose of each part of the function, including any key operations, conditionals, loops, and data structures involved. "
                                    + "Providea step-by-step explanation of how the function works and what its expected behavior would be when executed.\n"
                                    + "```json\n" + "<code>\n" + "```");
                    submit_btn.doClick();
                }).popupMenuPath(new String[] {"Explain using AI"}).popupMenuGroup("KinGAidra")
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

        log_action = new DockingAction("ChatLog", provider.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                JPanel p = new JPanel();
                if (lgui != null) {
                    p.add(lgui);
                }

                JOptionPane.showMessageDialog(null, p, "ChatLog", JOptionPane.PLAIN_MESSAGE);
            }
        };
        log_action.setToolBarData(new ToolBarData(Icons.MAKE_SELECTION_ICON, null));
        log_action.setEnabled(true);
        log_action.markHelpUnnecessary();
        dockingTool.addLocalAction(provider, log_action);
    }

    synchronized private boolean check_and_set_busy(boolean v) {
        if (v && busy) {
            return false;
        }
        busy = v;
        return true;
    }

    public void reset(Conversation convo) {
        if (!check_and_set_busy(true)) {
            Logger.append_message("Another process running");
            return;
        }
        restart_btn.setEnabled(false);
        submit_btn.setEnabled(false);
        info_label.setText("Working ...");
        try {
            cur_convo = convo;
            build_panel();
        } finally {
            info_label.setText("Finished!");
            restart_btn.setEnabled(true);
            submit_btn.setEnabled(true);
            check_and_set_busy(false);
            validate();
        }
    }

    public void guess(Address addr) {
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
                if (addr != null) {
                    if (cur_convo == null) {
                        cur_convo = ggui.run_guess(input_area.getText(), addr);
                    } else {
                        cur_convo = ggui.run_guess(cur_convo, input_area.getText(), addr);
                    }
                    if (cur_convo != null) {
                        container.add_convo(cur_convo);
                        lgui.update(program);
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
}