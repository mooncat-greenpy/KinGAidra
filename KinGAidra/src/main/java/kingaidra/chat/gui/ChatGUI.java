package kingaidra.chat.gui;

import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.AbstractMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
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
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelByScript;
import kingaidra.ai.model.ModelConf;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.ai.task.TaskType;
import kingaidra.chat.Guess;
import kingaidra.ghidra.PromptConf;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.gui.MainProvider;
import kingaidra.log.Logger;
import resources.Icons;
import resources.ResourceManager;

import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.data.MutableDataSet;
import com.vladsch.flexmark.html.HtmlRenderer;

public class ChatGUI extends JPanel {

    private JTextArea input_area;
    private JButton restart_btn;
    private JButton submit_btn;
    private JButton delete_btn;
    private JLabel info_label;
    private JPanel btn_panel;
    private JCheckBox md_chk;

    private DockingAction log_action;

    private Program program;
    private PluginTool plugin;
    private KinGAidraChatTaskService srv;
    private GhidraUtil ghidra;
    private ModelConf model_conf;
    private PromptConf conf;
    private ConversationContainer container;
    private Ai ai;
    private Logger logger;
    private GuessGUI ggui;
    private LogGUI lgui;
    private Conversation cur_convo;

    private boolean busy;
    private boolean add_comments_busy;

    public ChatGUI(MainProvider provider, Tool dockingTool, Program program, Plugin plugin,
            String owner, KinGAidraChatTaskService srv, GhidraUtil ghidra, ModelConf model_conf, PromptConf conf, ConversationContainer container, Ai ai, Logger logger) {
        super();
        this.program = program;
        this.plugin = plugin.getTool();
        this.srv = srv;
        this.ghidra = ghidra;
        this.model_conf = model_conf;
        this.conf = conf;
        this.container = container;
        this.ai = ai;
        this.logger = logger;
        check_and_set_busy(false);
        check_and_set_add_comments_busy(false);
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

    private String format_tool_calls(List<Map<String, Object>> tool_calls) {
        if (tool_calls == null || tool_calls.isEmpty()) {
            return null;
        }
        StringBuilder content = new StringBuilder();
        content.append("Tool call(s):");
        for (Map<String, Object> call : tool_calls) {
            if (call == null) {
                continue;
            }
            Object func_obj = call.get("function");
            String name = null;
            String args = null;
            if (func_obj instanceof Map) {
                Map<?, ?> func = (Map<?, ?>) func_obj;
                Object name_obj = func.get("name");
                Object args_obj = func.get("arguments");
                name = name_obj == null ? null : name_obj.toString();
                args = args_obj == null ? null : args_obj.toString();
            }
            content.append("\n- ");
            content.append(name == null ? "tool_call" : name);
            if (args != null && !args.isEmpty()) {
                content.append(": ").append(args);
            }
        }
        return content.toString();
    }

    private String get_display_text(String role, String content, String tool_call_id,
            List<Map<String, Object>> tool_calls) {
        if (content != null && !content.isEmpty()) {
            return content;
        }
        String tool_calls_text = format_tool_calls(tool_calls);
        if (tool_calls_text != null && !tool_calls_text.isEmpty()) {
            return tool_calls_text;
        }
        if (Conversation.TOOL_ROLE.equals(role)) {
            if (tool_call_id != null && !tool_call_id.isEmpty()) {
                return "Tool result (" + tool_call_id + "): (empty)";
            }
            return "Tool result: (empty)";
        }
        return "";
    }

    private void build_panel() {
        removeAll();

        btn_panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btn_panel.setAlignmentX(LEFT_ALIGNMENT);
        info_label = new JLabel();
        info_label.setPreferredSize(new Dimension(0, 40));
        restart_btn = new JButton("Clean");
        submit_btn = new JButton("Submit");
        delete_btn = new JButton("Delete");
        Dimension button_size = new Dimension(100, 40);

        restart_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                reset(null);
            }
        });
        restart_btn.setPreferredSize(button_size);
        restart_btn.setToolTipText("Next chat");
        btn_panel.add(restart_btn);

        submit_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                guess(TaskType.CHAT, ghidra.get_current_addr());
            }
        });
        submit_btn.setPreferredSize(button_size);
        submit_btn.setToolTipText("Send message to llm");
        btn_panel.add(submit_btn);

        delete_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (cur_convo == null) {
                    return;
                }
                container.del_convo(cur_convo.get_uuid());
                reset(null);
            }
        });
        delete_btn.setPreferredSize(button_size);
        delete_btn.setToolTipText("Delete chat from history");
        btn_panel.add(delete_btn);

        btn_panel.add(md_chk);

        input_area = new JTextArea("");
        input_area.setLineWrap(true);
        input_area.setWrapStyleWord(true);


        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        Border line_border = new LineBorder(getBackground(), 10, true);
        if (cur_convo != null) {
            for (int i = 0; i < cur_convo.get_msgs_len(); i++) {
                JPanel msg_panel = new JPanel();
                msg_panel.setLayout(new BoxLayout(msg_panel, BoxLayout.X_AXIS));
                msg_panel.setBorder(line_border);

                String role = cur_convo.get_role(i);
                String text = cur_convo.get_msg(i);
                String tool_call_id = cur_convo.get_tool_call_id(i);
                List<Map<String, Object>> tool_calls = cur_convo.get_tool_calls(i);
                text = get_display_text(role, text, tool_call_id, tool_calls);
                JEditorPane edit_panel = new JEditorPane();
                if (md_chk.isSelected()) {
                    text = convert_md_to_html(text);
                    edit_panel.setContentType("text/html");
                }
                edit_panel.setText(text);
                edit_panel.setEditable(false);

                JLabel role_label = new JLabel(role);
                role_label.setPreferredSize(new Dimension(50, 0));

                if (Conversation.USER_ROLE.equals(role)) {
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
        Guess guess = new Guess(ai, model_conf, conf);

        Model chatgptlike_model =
                new ModelByScript("ChatGPTLike", "kingaidra_chat.py", true);
        if (!guess.get_model_conf().exist_model(chatgptlike_model.get_name())) {
            guess.get_model_conf().add_model(chatgptlike_model.get_name(), chatgptlike_model.get_script());
            guess.get_model_conf().set_model_status(chatgptlike_model.get_name(), chatgptlike_model.get_active());
        }
        Model langchain_model =
                new ModelByScript("LangChain", "kingaidra_chat_langchain.py", false);
        if (!guess.get_model_conf().exist_model(langchain_model.get_name())) {
            guess.get_model_conf().add_model(langchain_model.get_name(), langchain_model.get_script());
            guess.get_model_conf().set_model_status(langchain_model.get_name(), langchain_model.get_active());
        }
        Model gencopytext_model =
                new ModelByScript("CopyTextGen", "kingaidra_gen_copy_text.py", false);
        if (!guess.get_model_conf().exist_model(gencopytext_model.get_name())) {
            guess.get_model_conf().add_model(gencopytext_model.get_name(), gencopytext_model.get_script());
            guess.get_model_conf().set_model_status(gencopytext_model.get_name(), gencopytext_model.get_active());
        }


        ggui = new GuessGUI(guess, logger);
        lgui = new LogGUI(container, this, plugin, program, logger);

        md_chk = new JCheckBox("markdown");

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
                        logger.append_message("Function not found");
                        return;
                    }

                    provider.setVisible(true);
                    provider.toFront();
                    provider.change_tab("Chat");

                    reset(null);
                    guess(TaskType.CHAT_EXPLAIN_DECOM, ghidra.get_current_addr());
                }).popupMenuPath(new String[] {"Explain using AI"}).popupMenuGroup("KinGAidra")
                .buildAndInstall(plugin);

        new ActionBuilder("Explain asm with AI", provider.getName())
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
                    provider.change_tab("Chat");

                    reset(null);
                    guess(TaskType.CHAT_EXPLAIN_ASM, ghidra.get_current_addr());
                }).popupMenuPath(new String[] {"Explain asm with AI"}).popupMenuGroup("KinGAidra")
                .buildAndInstall(plugin);

        new ActionBuilder("Decompile with AI", provider.getName())
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
                    provider.change_tab("Chat");

                    reset(null);
                    guess(TaskType.CHAT_DECOM_ASM, ghidra.get_current_addr());
                }).popupMenuPath(new String[] {"Decompile using AI"}).popupMenuGroup("KinGAidra")
                .buildAndInstall(plugin);

        new ActionBuilder("Explain strings (malware)", provider.getName())
                .withContext(ProgramLocationActionContext.class).enabledWhen(context -> {
                    return true;
                }).onAction(context -> {
                    provider.setVisible(true);
                    provider.toFront();
                    provider.change_tab("Chat");

                    reset(null);
                    guess(TaskType.CHAT_EXPLAIN_STRINGS, ghidra.get_current_addr());
                }).popupMenuPath(new String[] {"Explain strings (malware)"}).popupMenuGroup("KinGAidra")
                .buildAndInstall(plugin);

        new ActionBuilder("Add comments using AI", provider.getName())
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

                    if (!check_and_set_add_comments_busy(true)) {
                        logger.append_message("Another process running");
                        return;
                    }
                    logger.append_message("Start: Add comments");
                    Thread th = new Thread(() -> {
                        try {
                            Address addr = ghidra.get_current_addr();
                            ghidra.clear_comments(addr);
                            List<Map.Entry<String, String>> comments = ggui.run_guess_src_code_comments(addr);
                            ghidra.add_comments(addr, comments);
                        } finally {
                            check_and_set_add_comments_busy(false);
                            logger.append_message("Finish: Add comments");
                        }
                    });
                    th.start();
                }).popupMenuPath(new String[] {"Add comments using AI"}).popupMenuGroup("KinGAidra")
                .buildAndInstall(plugin);


        log_action = new DockingAction("History", provider.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                JPanel p = new JPanel();
                if (lgui != null) {
                    lgui.update(program);
                    p.add(lgui);
                }

                JOptionPane.showMessageDialog(null, p, "History", JOptionPane.PLAIN_MESSAGE);
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

    synchronized private boolean check_and_set_add_comments_busy(boolean v) {
        if (v && add_comments_busy) {
            return false;
        }
        add_comments_busy = v;
        return true;
    }

    public void reset(Conversation convo) {
        if (!check_and_set_busy(true)) {
            logger.append_message("Another process running");
            return;
        }
        restart_btn.setEnabled(false);
        submit_btn.setEnabled(false);
        delete_btn.setEnabled(false);
        info_label.setText("Working ...");
        try {
            cur_convo = convo;
            build_panel();
        } finally {
            info_label.setText("Finished!");
            restart_btn.setEnabled(true);
            submit_btn.setEnabled(true);
            delete_btn.setEnabled(true);
            check_and_set_busy(false);
            validate();
            repaint();
        }
    }

    public void guess(TaskType type, Address addr) {
        if (!check_and_set_busy(true)) {
            logger.append_message("Another process running");
            return;
        }
        restart_btn.setEnabled(false);
        submit_btn.setEnabled(false);
        delete_btn.setEnabled(false);
        info_label.setText("Working ...");
        SwingWorker<Conversation, Void> worker = new SwingWorker<>() {
            @Override
            protected Conversation doInBackground() {
                if (addr == null) {
                    return cur_convo;
                 }
                 if (cur_convo == null) {
                    return ggui.run_guess(type, input_area.getText(), addr);
                }
                return ggui.run_guess(type, cur_convo, input_area.getText(), addr);
            }

            @Override
            protected void done() {
                try {
                    cur_convo = get();
                    build_panel();
                    info_label.setText(cur_convo == null ? "Failed!" : "Finished!");
                } catch (Exception e) {
                    cur_convo = null;
                     info_label.setText("Failed!");
                } finally {
                    restart_btn.setEnabled(true);
                    submit_btn.setEnabled(true);
                    delete_btn.setEnabled(true);
                    check_and_set_busy(false);
                    validate();
                    repaint();
                 }
             }
        };
        worker.execute();

        validate();
    }
}
