package kingaidra.chat.gui;

import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.image.BufferedImage;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import javax.swing.text.BadLocationException;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.Tool;
import ghidra.app.services.GoToService;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.action.builder.ActionBuilder;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelByScript;
import kingaidra.ai.model.ModelConf;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.ai.task.TaskType;
import kingaidra.chat.Guess;
import kingaidra.chat.workflow.ChatWorkflow;
import kingaidra.ghidra.PromptConf;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.gui.MainProvider;
import kingaidra.log.Logger;
import resources.Icons;

public class ChatGUI extends JPanel {
    private static final String TOOL_OPTIONS_ROOT = "KinGAidra";
    private static final Pattern ADDRESS_TOKEN_PATTERN = Pattern.compile("(?i)0x[0-9a-f]+");
    private static final Pattern IDENTIFIER_TOKEN_PATTERN = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");

    private JTextArea input_area;
    private JButton restart_btn;
    private JButton submit_btn;
    private JButton delete_btn;
    private JButton refresh_btn;
    private JLabel info_label;
    private JPanel btn_panel;
    private JCheckBox md_chk;
    private JCheckBox tool_chk;

    private DockingAction log_action;
    private final List<DockingAction> workflow_actions = new ArrayList<>();
    private OptionsChangeListener workflow_options_listener;

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
    private MarkdownHtmlRenderer md_html_renderer;
    private MarkdownPlantUmlExtractor md_plantuml_extractor;

    private boolean busy;
    private boolean add_comments_busy;
    private boolean history_read_only;

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
        init_md_viewer();

        init_panel();

        setVisible(true);
    }

    private void init_md_viewer() {
        md_html_renderer = new MarkdownHtmlRenderer();
        md_plantuml_extractor = new MarkdownPlantUmlExtractor();
    }

    private JComponent build_plain_text_component(String text) {
        JEditorPane edit_panel = new JEditorPane();
        edit_panel.setText(text);
        edit_panel.setEditable(false);
        return edit_panel;
    }

    private JComponent build_markdown_text_component(String markdown) {
        JEditorPane edit_panel = new JEditorPane();
        edit_panel.setContentType("text/html");
        edit_panel.setText("<html><body>" + md_html_renderer.render(markdown) + "</body></html>");
        edit_panel.setEditable(false);
        install_markdown_navigation(edit_panel);
        return edit_panel;
    }

    private void install_markdown_navigation(JEditorPane edit_panel) {
        edit_panel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() != 1 || !SwingUtilities.isLeftMouseButton(e)) {
                    return;
                }
                int pos = edit_panel.viewToModel2D(e.getPoint());
                String token = resolve_click_token(edit_panel, pos);
                if (token == null) {
                    return;
                }
                if (is_address_token(token)) {
                    navigate_to_address_token(token);
                    return;
                }
                if (is_identifier_token(token)) {
                    navigate_to_symbol_function(token);
                }
            }
        });
    }

    private String resolve_click_token(JEditorPane edit_panel, int pos) {
        try {
            int len = edit_panel.getDocument().getLength();
            if (pos >= len) {
                pos = len - 1;
            }
            String text = edit_panel.getDocument().getText(0, len);
            if (text.isEmpty()) {
                return null;
            }
            if (!is_token_char(text.charAt(pos))) {
                if (pos > 0 && is_token_char(text.charAt(pos - 1))) {
                    pos--;
                } else {
                    return null;
                }
            }
            int start = pos;
            while (start > 0 && is_token_char(text.charAt(start - 1))) {
                start--;
            }
            int end = pos + 1;
            while (end < text.length() && is_token_char(text.charAt(end))) {
                end++;
            }
            return text.substring(start, end);
        } catch (BadLocationException ex) {
            return null;
        }
    }

    private boolean is_token_char(char ch) {
        return Character.isLetterOrDigit(ch) || ch == '_';
    }

    private boolean is_address_token(String token) {
        return ADDRESS_TOKEN_PATTERN.matcher(token).matches();
    }

    private boolean is_identifier_token(String token) {
        return IDENTIFIER_TOKEN_PATTERN.matcher(token).matches();
    }

    private void navigate_to_address_token(String token) {
        if (token.length() < 3) {
            return;
        }
        Address addr;
        try {
            long addr_value = Long.parseUnsignedLong(token.substring(2), 16);
            addr = ghidra.get_addr(addr_value);
        } catch (NumberFormatException ex) {
            return;
        }
        if (addr == null) {
            return;
        }
        navigate_to_address(addr);
    }

    private void navigate_to_symbol_function(String symbol) {
        Function func = resolve_function_by_name(symbol);
        if (func == null) {
            return;
        }
        navigate_to_address(func.getEntryPoint());
    }

    private Function resolve_function_by_name(String name) {
        if (name.isEmpty()) {
            return null;
        }
        List<Function> funcs = ghidra.get_func(name);
        if (funcs.isEmpty()) {
            return null;
        }
        return funcs.get(0);
    }

    private void navigate_to_address(Address addr) {
        GoToService go_to_service = plugin.getService(GoToService.class);
        if (go_to_service == null) {
            logger.append_message("GoTo service unavailable");
            return;
        }
        go_to_service.goTo(addr, program);
    }

    private String escape_html(String src) {
        if (src == null) {
            return "";
        }
        return src.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private JComponent build_plantuml_component(String plantuml_src) {
        try {
            BufferedImage img = PlantUmlRenderer.render_plantuml_png(plantuml_src);
            JLabel label = new JLabel(new ImageIcon(img));
            label.setVerticalAlignment(SwingConstants.TOP);
            label.setHorizontalAlignment(SwingConstants.LEFT);
            label.setAlignmentX(LEFT_ALIGNMENT);

            JPanel wrapper = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            wrapper.setAlignmentX(LEFT_ALIGNMENT);
            wrapper.add(label);
            return wrapper;
        } catch (Exception e) {
            logger.append_message("PlantUML render failed: " + e.getMessage());
            String html = "<html><body><b>PlantUML render failed.</b><pre>"
                    + escape_html(plantuml_src) + "</pre></body></html>";
            JEditorPane edit_panel = new JEditorPane();
            edit_panel.setContentType("text/html");
            edit_panel.setText(html);
            edit_panel.setEditable(false);
            return edit_panel;
        }
    }

    private JComponent build_markdown_component(String markdown) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        List<MarkdownPlantUmlExtractor.Segment> segments =
                md_plantuml_extractor.split_segments(markdown);
        for (MarkdownPlantUmlExtractor.Segment segment : segments) {
            JComponent segment_component;
            if (segment.is_plantuml()) {
                segment_component = build_plantuml_component(segment.get_content());
            } else {
                if (segment.get_content() == null || segment.get_content().isEmpty()) {
                    continue;
                }
                segment_component = build_markdown_text_component(segment.get_content());
            }
            segment_component.setAlignmentX(LEFT_ALIGNMENT);
            panel.add(segment_component);
        }
        if (panel.getComponentCount() == 0) {
            JComponent empty = build_markdown_text_component("");
            empty.setAlignmentX(LEFT_ALIGNMENT);
            panel.add(empty);
        }
        return panel;
    }

    private JComponent build_message_component(String text) {
        if (md_chk == null || !md_chk.isSelected()) {
            return build_plain_text_component(text);
        }
        return build_markdown_component(text);
    }

    private void apply_history_view_state() {
        boolean editable = !history_read_only;
        if (input_area != null) {
            input_area.setEditable(editable);
        }
        if (submit_btn != null) {
            submit_btn.setEnabled(editable);
        }
    }

    private boolean is_history_read_only_conversation(Conversation convo) {
        if (convo == null) {
            return false;
        }
        ConversationType type = convo.get_type();
        if (type == null) {
            return false;
        }
        return type == ConversationType.SYSTEM_DECOM
                || type == ConversationType.SYSTEM_DECOMPILE_VIEW
                || type == ConversationType.SYSTEM_KEYFUNC;
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

    private boolean show_message(String role) {
        if (tool_chk == null || tool_chk.isSelected()) {
            return true;
        }
        if (Conversation.TOOL_ROLE.equals(role)) {
            return false;
        }
        return true;
    }

    private void build_panel() {
        removeAll();

        btn_panel = new JPanel();
        btn_panel.setLayout(new FlowLayout(FlowLayout.LEFT, 0, 0));
        btn_panel.setAlignmentX(LEFT_ALIGNMENT);
        info_label = new JLabel();
        info_label.setPreferredSize(new Dimension(0, 40));
        restart_btn = new JButton("Clean");
        submit_btn = new JButton("Submit");
        delete_btn = new JButton("Delete");
        refresh_btn = new JButton("Refresh");
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
        btn_panel.add(tool_chk);

        refresh_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String input_text = (input_area == null) ? "" : input_area.getText();
                build_panel();
                input_area.setText(input_text);
                validate();
                repaint();
            }
        });
        refresh_btn.setPreferredSize(button_size);
        refresh_btn.setToolTipText("Refresh chat view");
        btn_panel.add(refresh_btn);

        input_area = new JTextArea("");
        input_area.setLineWrap(true);
        input_area.setWrapStyleWord(true);
        input_area.setAlignmentX(LEFT_ALIGNMENT);


        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        Border line_border = new LineBorder(getBackground(), 10, true);
        if (cur_convo != null) {
            for (int i = 0; i < cur_convo.get_msgs_len(); i++) {
                JPanel msg_panel = new JPanel();
                msg_panel.setLayout(new BoxLayout(msg_panel, BoxLayout.X_AXIS));
                msg_panel.setAlignmentX(LEFT_ALIGNMENT);
                msg_panel.setBorder(line_border);

                String role = cur_convo.get_role(i);
                String text = cur_convo.get_msg(i);
                String tool_call_id = cur_convo.get_tool_call_id(i);
                List<Map<String, Object>> tool_calls = cur_convo.get_tool_calls(i);
                if (!show_message(role)) {
                    continue;
                }
                text = get_display_text(role, text, tool_call_id, tool_calls);
                JComponent msg_component = build_message_component(text);

                JLabel role_label = new JLabel(role);
                role_label.setPreferredSize(new Dimension(50, 0));

                if (Conversation.USER_ROLE.equals(role)) {
                    msg_panel.add(role_label);
                    msg_panel.add(msg_component);
                } else {
                    msg_panel.add(msg_component);
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
        apply_history_view_state();

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
        Model codex_model =
                new ModelByScript("Codex", "kingaidra_chat_codex.py", false);
        if (!guess.get_model_conf().exist_model(codex_model.get_name())) {
            guess.get_model_conf().add_model(codex_model.get_name(), codex_model.get_script());
            guess.get_model_conf().set_model_status(codex_model.get_name(), codex_model.get_active());
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
        tool_chk = new JCheckBox("tool");

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

        new ActionBuilder("Quick malware behavior overview with AI", provider.getName())
                .withContext(ProgramLocationActionContext.class).enabledWhen(context -> {
                    return true;
                }).onAction(context -> {
                    provider.setVisible(true);
                    provider.toFront();
                    provider.change_tab("Chat");

                    reset(null);
                    guess(TaskType.CHAT_MALWARE_BEHAVIOR_OVERVIEW, ghidra.get_current_addr());
                }).popupMenuPath(new String[] {"Quick malware behavior overview with AI"}).popupMenuGroup("KinGAidra")
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

        install_workflow_actions(provider);
        register_workflow_options_listener(provider);

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

    private void register_workflow_options_listener(MainProvider provider) {
        if (workflow_options_listener != null) {
            return;
        }

        ToolOptions options = plugin.getOptions(TOOL_OPTIONS_ROOT);
        workflow_options_listener = (changed_options, option_name, old_value, new_value) -> {
            if (option_name == null ||
                    !option_name.endsWith(PromptConf.OPTION_WORKFLOWS_JSON)) {
                return;
            }
            SwingUtilities.invokeLater(() -> install_workflow_actions(provider));
        };
        options.addOptionsChangeListener(workflow_options_listener);
    }

    private void clear_workflow_actions() {
        for (DockingAction action : workflow_actions) {
            plugin.removeAction(action);
        }
        workflow_actions.clear();
    }

    private void install_workflow_actions(MainProvider provider) {
        clear_workflow_actions();

        List<ChatWorkflow> workflows = conf.get_workflows();
        for (int i = 0; i < workflows.size(); i++) {
            final ChatWorkflow workflow = workflows.get(i);
            String popup_name = workflow.get_popup_name();
            if (popup_name == null || popup_name.isEmpty()) {
                continue;
            }

            String action_name = String.format("Custom Workflow using AI (%d): %s", i + 1, popup_name);
            DockingAction action = new ActionBuilder(action_name, provider.getName())
                    .withContext(ProgramLocationActionContext.class)
                    .enabledWhen(context -> true)
                    .onAction(context -> {
                        provider.setVisible(true);
                        provider.toFront();
                        provider.change_tab("Chat");

                        reset(null);
                        guess_workflow(workflow, ghidra.get_current_addr());
                    }).popupMenuPath(new String[] {"Custom Workflow using AI", popup_name})
                    .popupMenuGroup("KinGAidra")
                    .buildAndInstall(plugin);
            workflow_actions.add(action);
        }
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
            if (convo == null) {
                return;
            }
            logger.append_message("Another process running");
            return;
        }
        restart_btn.setEnabled(false);
        submit_btn.setEnabled(false);
        delete_btn.setEnabled(false);
        refresh_btn.setEnabled(false);
        info_label.setText("Working ...");
        try {
            cur_convo = convo;
            history_read_only = is_history_read_only_conversation(convo);
            build_panel();
        } finally {
            info_label.setText("Finished!");
            restart_btn.setEnabled(true);
            submit_btn.setEnabled(!history_read_only);
            delete_btn.setEnabled(true);
            refresh_btn.setEnabled(true);
            apply_history_view_state();
            check_and_set_busy(false);
            validate();
            repaint();
        }
    }

    public void guess(TaskType type, Address addr) {
        if (history_read_only) {
            logger.append_message("History view is read-only");
            return;
        }
        final boolean show_in_chat_tab = check_and_set_busy(true);
        final Conversation base_convo = show_in_chat_tab ? cur_convo : null;
        final String input_text = input_area.getText();
        if (show_in_chat_tab) {
            restart_btn.setEnabled(false);
            submit_btn.setEnabled(false);
            delete_btn.setEnabled(false);
            refresh_btn.setEnabled(false);
            info_label.setText("Working ...");
        }
        SwingWorker<Conversation, Void> worker = new SwingWorker<>() {
            @Override
            protected Conversation doInBackground() {
                if (addr == null) {
                    return base_convo;
                }
                if (base_convo == null) {
                    return ggui.run_guess(type, input_text, addr);
                }
                return ggui.run_guess(type, base_convo, input_text, addr);
            }

            @Override
            protected void done() {
                if (!show_in_chat_tab) {
                    return;
                }
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
                    refresh_btn.setEnabled(true);
                    check_and_set_busy(false);
                    validate();
                    repaint();
                }
            }
        };
        worker.execute();

        if (show_in_chat_tab) {
            validate();
        }
    }

    public void guess_workflow(ChatWorkflow workflow, Address addr) {
        final boolean show_in_chat_tab = check_and_set_busy(true);
        final Conversation base_convo = cur_convo;
        if (show_in_chat_tab) {
            restart_btn.setEnabled(false);
            submit_btn.setEnabled(false);
            delete_btn.setEnabled(false);
            refresh_btn.setEnabled(false);
            info_label.setText("Working ...");
        }
        SwingWorker<Conversation, Void> worker = new SwingWorker<>() {
            @Override
            protected Conversation doInBackground() {
                if (addr == null) {
                    return base_convo;
                }
                return ggui.run_workflow(workflow, addr);
            }

            @Override
            protected void done() {
                if (!show_in_chat_tab) {
                    return;
                }
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
                    refresh_btn.setEnabled(true);
                    check_and_set_busy(false);
                    validate();
                    repaint();
                }
            }
        };
        worker.execute();

        if (show_in_chat_tab) {
            validate();
        }
    }
}
