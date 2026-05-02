package kingaidra.decom.gui;

import java.awt.Color;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.CaretEvent;
import javax.swing.event.CaretListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import docking.Tool;
import docking.action.builder.ActionBuilder;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.ModelConf;
import kingaidra.decom.LlmDecompile;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.PromptConf;
import kingaidra.gui.MainProvider;
import kingaidra.ai.Ai;
import kingaidra.log.Logger;

public class LlmDecompileGUI extends JPanel {
    private static final String MSG_NO_FUNCTION =
            "/* Move the cursor into a function to view LLM decompile output. */";
    private static final String MSG_NO_OUTPUT =
            "/* No LLM output for this function. Run 'Decompile using AI (view)'. */";
    private static final Pattern IDENTIFIER_PATTERN = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");
    private static final int MAX_SYMBOL_TEXT_LENGTH = 256;
    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private Program program;
    private PluginTool plugin;
    private MainProvider provider;
    private GhidraUtil ghidra;
    private DecomGUI decom_gui;
    private ConversationContainer container;
    private Logger logger;
    private LlmDecompile llm_decompile;
    private List<SavedResult> decompile_saved_results;

    private JLabel info_label;
    private JLabel func_label;
    private JButton regen_btn;
    private JButton refactor_btn;
    private JButton instruction_btn;
    private JButton copy_btn;
    private JButton search_prev_btn;
    private JButton search_next_btn;
    private JComboBox<FunctionSelectionItem> function_selector;
    private JTextField instruction_field;
    private JTextField search_field;
    private JLabel search_status_label;
    private RSyntaxTextArea code_area;
    private Address current_func_entry;
    private boolean updating_function_selector;
    private String location_selected_symbol;
    private String local_selected_symbol;
    private boolean suppress_code_area_caret_listener;
    private String search_query;
    private int search_match_index;
    private List<SearchMatch> search_matches;
    private List<Object> symbol_highlight_tags;
    private List<Object> search_highlight_tags;
    private Object active_search_highlight_tag;

    private final Highlighter.HighlightPainter symbol_highlight_painter =
            new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 244, 170));
    private final Highlighter.HighlightPainter search_highlight_painter =
            new DefaultHighlighter.DefaultHighlightPainter(new Color(202, 231, 255));
    private final Highlighter.HighlightPainter active_search_highlight_painter =
            new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 193, 122));

    private boolean busy;

    private static class SavedResult {
        private Address entry;
        private String code;
        private String updated;

        SavedResult(Address entry, String code, String updated) {
            this.entry = entry;
            this.code = code;
            this.updated = updated;
        }
    }

    private static class SearchMatch {
        private int start;
        private int end;

        SearchMatch(int start, int end) {
            this.start = start;
            this.end = end;
        }
    }

    private static class FunctionSelectionItem {
        private SavedResult result;
        private String label;

        FunctionSelectionItem(SavedResult result, String label) {
            this.result = result;
            this.label = label;
        }

        public SavedResult get_result() {
            return result;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    public LlmDecompileGUI(MainProvider provider, Tool dockingTool, Program program, Plugin plugin,
            String owner, GhidraUtil ghidra, ConversationContainer container, ModelConf model_conf, PromptConf conf,
            Ai ai, Logger logger, DecomGUI decom_gui) {
        super();
        this.program = program;
        this.plugin = plugin.getTool();
        this.provider = provider;
        this.ghidra = ghidra;
        this.decom_gui = decom_gui;
        this.container = container;
        this.logger = logger;
        this.llm_decompile = new LlmDecompile(ai, ghidra, model_conf, conf);
        this.decompile_saved_results = new ArrayList<>();
        this.current_func_entry = null;
        this.updating_function_selector = false;
        this.location_selected_symbol = null;
        this.local_selected_symbol = null;
        this.suppress_code_area_caret_listener = false;
        this.search_query = "";
        this.search_match_index = -1;
        this.search_matches = new ArrayList<>();
        this.symbol_highlight_tags = new ArrayList<>();
        this.search_highlight_tags = new ArrayList<>();
        this.active_search_highlight_tag = null;
        check_and_set_busy(false);
        setLayout(new BorderLayout());
        build_panel();
        run_load_saved_results();
        setVisible(true);
    }

    private void build_panel() {
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));

        JPanel button_panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        regen_btn = new JButton("Regenerate");
        refactor_btn = new JButton("Send to Refactor");
        instruction_btn = new JButton("Apply Instruction");
        copy_btn = new JButton("Copy");
        info_label = new JLabel("");
        func_label = new JLabel("Function: (none)");
        function_selector = new JComboBox<>();
        instruction_field = new JTextField(48);
        search_field = new JTextField(20);
        search_prev_btn = new JButton("Prev");
        search_next_btn = new JButton("Next");
        search_status_label = new JLabel("0/0");
        function_selector.setPrototypeDisplayValue(
                new FunctionSelectionItem(null, "function_name @ 0x00000000 (yyyy-MM-dd HH:mm:ss)"));
        function_selector.setEnabled(false);
        search_prev_btn.setEnabled(false);
        search_next_btn.setEnabled(false);
        refactor_btn.setToolTipText("Generate refactoring candidates in the Refactor tab using this output");

        regen_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Function func = get_current_function();
                if (func == null) {
                    logger.append_message("Function not found");
                    return;
                }
                run_llm_decompile(func.getEntryPoint());
            }
        });
        instruction_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                run_llm_decompile_with_instruction();
            }
        });
        refactor_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                run_refactor_from_decompile_view();
            }
        });
        copy_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String content = code_area.getText();
                if (content == null || content.isEmpty()) {
                    return;
                }
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(content), null);
                info_label.setText("Copied");
            }
        });
        function_selector.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (updating_function_selector) {
                    return;
                }
                FunctionSelectionItem item =
                        (FunctionSelectionItem) function_selector.getSelectedItem();
                if (item == null || item.get_result() == null) {
                    return;
                }
                show_saved_result(item.get_result(), null, false);
            }
        });
        search_prev_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                move_search_match(-1);
            }
        });
        search_next_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                move_search_match(1);
            }
        });
        search_field.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                move_search_match(1);
            }
        });
        instruction_field.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                run_llm_decompile_with_instruction();
            }
        });
        search_field.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                refresh_search_matches(false);
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                refresh_search_matches(false);
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                refresh_search_matches(false);
            }
        });
        button_panel.add(regen_btn);
        button_panel.add(refactor_btn);
        button_panel.add(copy_btn);
        button_panel.add(info_label);

        JPanel instruction_panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        instruction_panel.add(new JLabel("Instruction:"));
        instruction_panel.add(instruction_field);
        instruction_panel.add(instruction_btn);

        JPanel function_selector_panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        function_selector_panel.add(new JLabel("Saved Version:"));
        function_selector_panel.add(function_selector);

        JPanel search_panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        search_panel.add(new JLabel("Search:"));
        search_panel.add(search_field);
        search_panel.add(search_prev_btn);
        search_panel.add(search_next_btn);
        search_panel.add(search_status_label);

        header.add(button_panel);
        header.add(instruction_panel);
        header.add(function_selector_panel);
        header.add(search_panel);
        header.add(func_label);
        add(header, BorderLayout.NORTH);

        code_area = new RSyntaxTextArea();
        code_area.setEditable(false);
        code_area.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_C);
        code_area.setCodeFoldingEnabled(true);
        code_area.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                handle_code_area_double_click(e);
            }
        });
        code_area.addCaretListener(new CaretListener() {
            @Override
            public void caretUpdate(CaretEvent e) {
                handle_code_area_caret_change();
            }
        });
        set_code(MSG_NO_FUNCTION);

        RTextScrollPane scroll = new RTextScrollPane(code_area);
        add(scroll, BorderLayout.CENTER);
    }

    public void initActions(MainProvider provider, Tool dockingTool) {
        new ActionBuilder("Decompile using AI (view)", provider.getName())
                .withContext(ProgramLocationActionContext.class).enabledWhen(context -> {
                    Function func = context.getProgram().getFunctionManager()
                            .getFunctionContaining(context.getAddress());
                    return func != null;
                }).onAction(context -> {
                    Function func = context.getProgram().getFunctionManager()
                            .getFunctionContaining(context.getAddress());
                    if (func == null) {
                        logger.append_message("Function not found");
                        return;
                    }

                    provider.setVisible(true);
                    provider.toFront();
                    provider.change_tab("DecomView");
                    run_llm_decompile(func.getEntryPoint());
                }).popupMenuPath(new String[] {"Decompile using AI (view)"})
                .popupMenuGroup("KinGAidra")
                .buildAndInstall(plugin);
    }

    public void update_location(ProgramLocation loc) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> update_location(loc));
            return;
        }
        if (loc == null || loc.getAddress() == null) {
            current_func_entry = null;
            clear_selected_symbol();
            func_label.setText("Function: (none)");
            set_code(MSG_NO_FUNCTION);
            return;
        }
        Function func = program.getFunctionManager().getFunctionContaining(loc.getAddress());
        if (func == null) {
            current_func_entry = null;
            clear_selected_symbol();
            func_label.setText("Function: (none)");
            set_code(MSG_NO_FUNCTION);
            return;
        }

        Address entry = func.getEntryPoint();
        current_func_entry = entry;
        SavedResult latest = get_latest_saved_result(entry);
        select_saved_result(latest);
        show_saved_result(latest, entry, true);
        local_selected_symbol = null;
        set_location_selected_symbol(resolve_selected_symbol(loc, func));
    }

    private Function get_current_function() {
        Address addr = ghidra.get_current_addr();
        if (addr == null) {
            return null;
        }
        return program.getFunctionManager().getFunctionContaining(addr);
    }

    private void set_operation_controls_enabled(boolean enabled) {
        regen_btn.setEnabled(enabled);
        refactor_btn.setEnabled(enabled);
        instruction_btn.setEnabled(enabled);
        instruction_field.setEnabled(enabled);
        function_selector.setEnabled(enabled && function_selector.getItemCount() > 0);
    }

    private void run_refactor_from_decompile_view() {
        SavedResult result = get_active_saved_result();
        if (result == null) {
            logger.append_message("Function not selected");
            info_label.setText("Function not selected");
            return;
        }

        String reference_code = result.code;
        if (reference_code == null || reference_code.trim().isEmpty()) {
            info_label.setText("No existing output");
            return;
        }

        if (decom_gui == null) {
            logger.append_message("Refactor tab not found");
            info_label.setText("Refactor tab not found");
            return;
        }

        boolean started = decom_gui.run_refactor_from_reference(result.entry, reference_code);
        if (started) {
            info_label.setText("Sent to Refactor");
            provider.change_tab("Refactor");
        }
    }

    private void run_llm_decompile_with_instruction() {
        String instruction = instruction_field.getText();
        if (instruction.trim().isEmpty()) {
            info_label.setText("Instruction is empty");
            return;
        }
        SavedResult result = get_active_saved_result();
        if (result == null) {
            logger.append_message("Function not selected");
            info_label.setText("Function not selected");
            return;
        }
        String current_code = result.code;
        if (current_code == null || current_code.trim().isEmpty()) {
            info_label.setText("No existing output");
            return;
        }
        run_llm_decompile(result.entry, instruction.trim(), current_code);
    }

    private void run_llm_decompile(Address func_entry) {
        run_llm_decompile(func_entry, null, null);
    }

    private void run_llm_decompile(Address func_entry, String instruction, String current_code) {
        if (func_entry == null) {
            return;
        }
        Function func = program.getFunctionManager().getFunctionAt(func_entry);
        if (func != null) {
            current_func_entry = func_entry;
            func_label.setText(String.format("Function: %s @ %s", func.getName(), func_entry));
            set_location_selected_symbol(func.getName());
        }
        if (!check_and_set_busy(true)) {
            logger.append_message("Another process running");
            return;
        }
        set_operation_controls_enabled(false);
        info_label.setText("Working ...");
        final String instruction_text = instruction;
        final String base_code = current_code;

        SwingWorker<String, Void> worker = new SwingWorker<>() {
            @Override
            protected String doInBackground() {
                if (instruction_text == null || instruction_text.isEmpty()) {
                    return llm_decompile.guess(func_entry);
                }
                return llm_decompile.guess(func_entry, instruction_text, base_code);
            }

            @Override
            protected void done() {
                try {
                    String code = get();
                    if (code != null && !code.isEmpty()) {
                        SavedResult result = new SavedResult(
                                func_entry, code, LocalDateTime.now().format(DATE_FORMAT));
                        merge_saved_result(result);
                        refresh_function_selector(result.entry, result);
                        if (instruction_text != null && !instruction_text.isEmpty()) {
                            instruction_field.setText("");
                        }
                        info_label.setText("Finished!");
                    } else {
                        info_label.setText("Failed!");
                    }
                } catch (Exception e) {
                    info_label.setText("Failed!");
                } finally {
                    if (current_func_entry != null && current_func_entry.equals(func_entry)) {
                        show_saved_result(get_latest_saved_result(func_entry), func_entry, true);
                    }
                    set_operation_controls_enabled(true);
                    check_and_set_busy(false);
                    validate();
                    repaint();
                }
            }
        };
        worker.execute();
    }

    private void run_load_saved_results() {
        if (container == null) {
            info_label.setText("History unavailable");
            return;
        }
        if (!check_and_set_busy(true)) {
            logger.append_message("Another process running");
            return;
        }
        set_operation_controls_enabled(false);
        info_label.setText("Loading ...");

        SwingWorker<List<SavedResult>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<SavedResult> doInBackground() {
                return get_saved_results();
            }

            @Override
            protected void done() {
                try {
                    List<SavedResult> saved = get();
                    merge_saved_results(saved);
                    refresh_function_selector(current_func_entry, null);
                    if (current_func_entry != null) {
                        show_saved_result(get_latest_saved_result(current_func_entry),
                                current_func_entry, true);
                    }
                    int total = decompile_saved_results.size();
                    info_label.setText(total > 0 ? ("Loaded " + total + " version(s)") : "No saved result");
                } catch (Exception e) {
                    info_label.setText("Load failed");
                } finally {
                    set_operation_controls_enabled(true);
                    check_and_set_busy(false);
                    validate();
                    repaint();
                }
            }
        };
        worker.execute();
    }

    private List<SavedResult> get_saved_results() {
        List<SavedResult> result_list = new ArrayList<>();
        UUID[] ids = container.get_ids();
        if (ids == null) {
            return result_list;
        }

        for (UUID id : ids) {
            Conversation convo = container.get_convo(id);
            if (!is_llm_decompile_conversation(convo)) {
                continue;
            }

            SavedResult result = get_saved_result_from_conversation(convo);
            if (result == null) {
                continue;
            }
            result_list.add(result);
        }
        return result_list;
    }

    private boolean is_llm_decompile_conversation(Conversation convo) {
        return convo != null && convo.get_type() == ConversationType.SYSTEM_DECOMPILE_VIEW;
    }

    private SavedResult get_saved_result_from_conversation(Conversation convo) {
        if (convo == null) {
            return null;
        }
        Address entry = get_entry_from_conversation(convo);
        if (entry == null) {
            return null;
        }
        String code = get_code_from_conversation(convo);
        if (code == null || code.isEmpty()) {
            return null;
        }
        String updated = convo.get_updated();
        if (updated == null || updated.isEmpty()) {
            updated = LocalDateTime.now().format(DATE_FORMAT);
        }
        return new SavedResult(entry, code, updated);
    }

    private Address get_entry_from_conversation(Conversation convo) {
        if (convo == null) {
            return null;
        }
        Address[] addrs = convo.get_addrs();
        if (addrs == null || addrs.length == 0) {
            return null;
        }
        Address match = null;
        for (Address addr : addrs) {
            if (addr == null) {
                continue;
            }
            if (match == null || addr.compareTo(match) < 0) {
                match = addr;
            }
        }
        if (match == null) {
            return null;
        }
        Function func = program.getFunctionManager().getFunctionContaining(match);
        if (func == null) {
            return match;
        }
        return func.getEntryPoint();
    }

    private String get_code_from_conversation(Conversation convo) {
        if (convo == null) {
            return null;
        }
        for (int i = convo.get_msgs_len() - 1; i >= 0; i--) {
            String role = convo.get_role(i);
            if (!Conversation.ASSISTANT_ROLE.equals(role)) {
                continue;
            }
            String msg = convo.get_msg(i);
            String code = LlmDecompile.normalize_code(msg);
            if (code == null || code.isEmpty()) {
                continue;
            }
            return code;
        }
        return null;
    }

    private void merge_saved_results(List<SavedResult> saved_results) {
        if (saved_results == null || saved_results.isEmpty()) {
            return;
        }
        for (SavedResult result : saved_results) {
            merge_saved_result(result);
        }
    }

    private void merge_saved_result(SavedResult result) {
        if (result == null || result.entry == null || result.code == null || result.code.isEmpty()) {
            return;
        }
        decompile_saved_results.add(result);
    }

    private boolean is_newer(String lhs, String rhs) {
        if (lhs == null || lhs.isEmpty()) {
            return false;
        }
        if (rhs == null || rhs.isEmpty()) {
            return true;
        }
        return lhs.compareTo(rhs) > 0;
    }

    private void refresh_function_selector(Address selected_entry, SavedResult selected_result) {
        List<SavedResult> results = new ArrayList<>(decompile_saved_results);
        results.sort(new Comparator<SavedResult>() {
            @Override
            public int compare(SavedResult left, SavedResult right) {
                String left_name = get_function_name(left.entry);
                String right_name = get_function_name(right.entry);
                int result = left_name.compareToIgnoreCase(right_name);
                if (result != 0) {
                    return result;
                }
                result = left.entry.toString().compareTo(right.entry.toString());
                if (result != 0) {
                    return result;
                }
                result = compare_updated_desc(left.updated, right.updated);
                if (result != 0) {
                    return result;
                }
                return Integer.compare(left.code.hashCode(), right.code.hashCode());
            }
        });

        DefaultComboBoxModel<FunctionSelectionItem> model = new DefaultComboBoxModel<>();
        for (SavedResult result : results) {
            model.addElement(new FunctionSelectionItem(result, get_function_label(result)));
        }

        updating_function_selector = true;
        function_selector.setModel(model);
        updating_function_selector = false;

        if (model.getSize() <= 0) {
            function_selector.setEnabled(false);
            return;
        }

        if (selected_result != null && select_saved_result(selected_result)) {
            function_selector.setEnabled(!busy);
            return;
        }

        Address preferred = selected_entry != null ? selected_entry : current_func_entry;
        if (preferred != null) {
            select_saved_result(get_latest_saved_result(preferred));
        } else {
            function_selector.setSelectedIndex(0);
        }
        function_selector.setEnabled(!busy);
    }

    private SavedResult get_latest_saved_result(Address entry) {
        if (entry == null) {
            return null;
        }
        SavedResult latest = null;
        for (SavedResult result : decompile_saved_results) {
            if (result == null || result.entry == null || !result.entry.equals(entry)) {
                continue;
            }
            if (latest == null || is_newer(result.updated, latest.updated)) {
                latest = result;
            }
        }
        return latest;
    }

    private int compare_updated_desc(String left, String right) {
        if (left == null || left.isEmpty()) {
            return (right == null || right.isEmpty()) ? 0 : 1;
        }
        if (right == null || right.isEmpty()) {
            return -1;
        }
        return right.compareTo(left);
    }

    private String get_function_name(Address entry) {
        Function func = program.getFunctionManager().getFunctionAt(entry);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(entry);
        }
        if (func == null) {
            return "(unknown)";
        }
        return func.getName();
    }

    private String get_function_label(SavedResult result) {
        if (result == null) {
            return "";
        }
        String label = String.format("%s @ %s", get_function_name(result.entry), result.entry);
        if (result.updated != null && !result.updated.isEmpty()) {
            return label + " (" + result.updated + ")";
        }
        return label;
    }

    private SavedResult get_selected_saved_result() {
        FunctionSelectionItem item = (FunctionSelectionItem) function_selector.getSelectedItem();
        if (item == null) {
            return null;
        }
        return item.get_result();
    }

    private SavedResult get_active_saved_result() {
        SavedResult selected = get_selected_saved_result();
        if (selected != null) {
            return selected;
        }
        return get_latest_saved_result(current_func_entry);
    }

    private boolean select_saved_result(SavedResult result) {
        if (result == null || function_selector.getItemCount() <= 0) {
            return false;
        }
        updating_function_selector = true;
        for (int i = 0; i < function_selector.getItemCount(); i++) {
            FunctionSelectionItem item = function_selector.getItemAt(i);
            if (item == null || item.get_result() == null) {
                continue;
            }
            if (item.get_result() == result) {
                function_selector.setSelectedIndex(i);
                updating_function_selector = false;
                return true;
            }
        }
        updating_function_selector = false;
        return false;
    }

    private void show_saved_result(SavedResult result, Address fallback_entry,
            boolean use_no_output_placeholder) {
        Address entry = result == null ? fallback_entry : result.entry;
        if (entry == null) {
            func_label.setText("Function: (none)");
            set_code(MSG_NO_FUNCTION);
            return;
        }
        func_label.setText(String.format("Function: %s @ %s", get_function_name(entry), entry));
        if (result == null || result.code == null) {
            if (!use_no_output_placeholder) {
                return;
            }
            set_code(MSG_NO_OUTPUT);
            return;
        }
        if (result.updated != null && !result.updated.isEmpty()) {
            func_label.setText(func_label.getText() + " (" + result.updated + ")");
        }
        set_code(result.code);
    }

    private void set_code(String code) {
        suppress_code_area_caret_listener = true;
        try {
            code_area.setText(code == null ? MSG_NO_OUTPUT : code);
            code_area.setCaretPosition(0);
        } finally {
            suppress_code_area_caret_listener = false;
        }
        local_selected_symbol = null;
        apply_symbol_highlight();
        refresh_search_matches(true);
    }

    private void clear_selected_symbol() {
        location_selected_symbol = null;
        local_selected_symbol = null;
        apply_symbol_highlight();
    }

    private void set_location_selected_symbol(String raw_symbol) {
        location_selected_symbol = normalize_symbol(raw_symbol);
        apply_symbol_highlight();
    }

    private String resolve_selected_symbol(ProgramLocation loc, Function func) {
        if (loc instanceof DecompilerLocation) {
            DecompilerLocation decom_loc = (DecompilerLocation) loc;
            String symbol = normalize_symbol(decom_loc.getTokenName());
            if (symbol != null) {
                return symbol;
            }
        }
        if (loc != null && loc.getAddress() != null) {
            Symbol primary = program.getSymbolTable().getPrimarySymbol(loc.getAddress());
            if (primary != null) {
                String symbol = normalize_symbol(primary.getName());
                if (symbol != null) {
                    return symbol;
                }
            }
        }
        if (func != null) {
            return normalize_symbol(func.getName());
        }
        return null;
    }

    private String normalize_symbol(String raw) {
        if (raw == null) {
            return null;
        }
        String text = raw.trim();
        if (text.isEmpty()) {
            return null;
        }
        if (text.length() > MAX_SYMBOL_TEXT_LENGTH) {
            text = text.substring(0, MAX_SYMBOL_TEXT_LENGTH);
        }
        if (is_identifier(text)) {
            return text;
        }

        Matcher matcher = IDENTIFIER_PATTERN.matcher(text);
        String best = null;
        while (matcher.find()) {
            String candidate = matcher.group();
            if (candidate == null || candidate.isEmpty()) {
                continue;
            }
            if (best == null || candidate.length() > best.length()) {
                best = candidate;
            }
        }
        return best;
    }

    private boolean is_identifier(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        if (!(Character.isLetter(value.charAt(0)) || value.charAt(0) == '_')) {
            return false;
        }
        for (int i = 1; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (!(Character.isLetterOrDigit(ch) || ch == '_')) {
                return false;
            }
        }
        return true;
    }

    private void apply_symbol_highlight() {
        clear_highlight_tags(symbol_highlight_tags);
        String selected_symbol = local_selected_symbol != null
                ? local_selected_symbol
                : location_selected_symbol;
        if (selected_symbol == null || selected_symbol.isEmpty()) {
            return;
        }
        List<SearchMatch> matches = find_matches(code_area.getText(), selected_symbol, true);
        add_highlights(matches, symbol_highlight_painter, symbol_highlight_tags);
    }

    private void handle_code_area_caret_change() {
        if (suppress_code_area_caret_listener || code_area == null) {
            return;
        }
        local_selected_symbol = resolve_symbol_from_code_area();
        apply_symbol_highlight();
    }

    private void handle_code_area_double_click(MouseEvent e) {
        if (e == null || e.getClickCount() != 2 || !SwingUtilities.isLeftMouseButton(e)) {
            return;
        }
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                String symbol = resolve_symbol_from_code_area();
                if (symbol == null) {
                    return;
                }
                navigate_to_symbol_function(symbol);
            }
        });
    }

    private void navigate_to_symbol_function(String symbol) {
        Function func = resolve_function_by_name(symbol);
        if (func == null || func.getEntryPoint() == null) {
            return;
        }
        GoToService go_to_service = plugin.getService(GoToService.class);
        if (go_to_service == null) {
            logger.append_message("GoTo service unavailable");
            return;
        }
        go_to_service.goTo(func.getEntryPoint(), program);
    }

    private Function resolve_function_by_name(String name) {
        if (name == null || name.isEmpty()) {
            return null;
        }
        List<Function> funcs = ghidra.get_func(name);
        if (funcs.isEmpty()) {
            return null;
        }
        Function result = null;
        for (Function func : funcs) {
            if (result == null || func.getEntryPoint().compareTo(result.getEntryPoint()) < 0) {
                result = func;
            }
        }
        return result;
    }

    private String resolve_symbol_from_code_area() {
        String selected_text = code_area.getSelectedText();
        if (selected_text != null && !selected_text.isEmpty()) {
            String symbol = normalize_symbol(selected_text);
            if (symbol != null) {
                return symbol;
            }
        }

        String text = code_area.getText();
        if (text == null || text.isEmpty()) {
            return null;
        }
        int caret = code_area.getCaretPosition();
        if (caret < 0) {
            return null;
        }
        if (caret >= text.length()) {
            caret = text.length() - 1;
        }
        if (caret < 0) {
            return null;
        }

        if (!is_identifier_char(text.charAt(caret))) {
            if (caret > 0 && is_identifier_char(text.charAt(caret - 1))) {
                caret--;
            } else {
                return null;
            }
        }

        int start = caret;
        while (start > 0 && is_identifier_char(text.charAt(start - 1))) {
            start--;
        }
        int end = caret + 1;
        while (end < text.length() && is_identifier_char(text.charAt(end))) {
            end++;
        }
        if (start >= end) {
            return null;
        }
        return normalize_symbol(text.substring(start, end));
    }

    private void move_search_match(int delta) {
        boolean query_changed = refresh_search_matches(true);
        if (search_matches.isEmpty()) {
            return;
        }
        if (!query_changed) {
            search_match_index = Math.floorMod(search_match_index + delta, search_matches.size());
            apply_active_search_highlight();
        }
    }

    private boolean refresh_search_matches(boolean keep_index) {
        if (search_field == null) {
            return false;
        }
        String next_query = search_field.getText();
        if (next_query == null) {
            next_query = "";
        }
        next_query = next_query.trim();
        boolean query_changed = !next_query.equals(search_query);
        search_query = next_query;

        int previous_index = search_match_index;
        search_match_index = -1;
        clear_highlight_tags(search_highlight_tags);
        clear_active_search_highlight();
        search_matches.clear();
        if (next_query.isEmpty()) {
            update_search_controls();
            update_search_status();
            return query_changed;
        }

        search_matches.addAll(find_matches(code_area.getText(), next_query, false));
        add_highlights(search_matches, search_highlight_painter, search_highlight_tags);
        if (!search_matches.isEmpty()) {
            if (!query_changed && keep_index && previous_index >= 0
                    && previous_index < search_matches.size()) {
                search_match_index = previous_index;
            } else {
                search_match_index = 0;
            }
            apply_active_search_highlight();
        }
        update_search_controls();
        update_search_status();
        return query_changed;
    }

    private void apply_active_search_highlight() {
        clear_active_search_highlight();
        if (search_match_index < 0 || search_match_index >= search_matches.size()) {
            update_search_status();
            return;
        }
        SearchMatch match = search_matches.get(search_match_index);
        try {
            active_search_highlight_tag =
                    code_area.getHighlighter().addHighlight(match.start, match.end,
                        active_search_highlight_painter);
            code_area.setCaretPosition(match.start);
            code_area.moveCaretPosition(match.end);
        } catch (BadLocationException e) {
            active_search_highlight_tag = null;
        }
        update_search_status();
    }

    private void clear_active_search_highlight() {
        if (active_search_highlight_tag == null) {
            return;
        }
        code_area.getHighlighter().removeHighlight(active_search_highlight_tag);
        active_search_highlight_tag = null;
    }

    private void update_search_controls() {
        boolean has_match = !search_matches.isEmpty();
        search_prev_btn.setEnabled(has_match);
        search_next_btn.setEnabled(has_match);
    }

    private void update_search_status() {
        if (search_status_label == null) {
            return;
        }
        if (search_matches.isEmpty()) {
            search_status_label.setText("0/0");
            return;
        }
        search_status_label.setText(String.format("%d/%d", search_match_index + 1, search_matches.size()));
    }

    private List<SearchMatch> find_matches(String text, String needle, boolean word_boundary_only) {
        List<SearchMatch> matches = new ArrayList<>();
        if (text == null || text.isEmpty() || needle == null || needle.isEmpty()) {
            return matches;
        }
        int from = 0;
        while (from <= text.length() - needle.length()) {
            int start = text.indexOf(needle, from);
            if (start < 0) {
                break;
            }
            int end = start + needle.length();
            if (!word_boundary_only || is_identifier_boundary(text, start, end)) {
                matches.add(new SearchMatch(start, end));
            }
            from = start + 1;
        }
        return matches;
    }

    private boolean is_identifier_boundary(String text, int start, int end) {
        boolean left_ok = start <= 0 || !is_identifier_char(text.charAt(start - 1));
        boolean right_ok = end >= text.length() || !is_identifier_char(text.charAt(end));
        return left_ok && right_ok;
    }

    private boolean is_identifier_char(char ch) {
        return Character.isLetterOrDigit(ch) || ch == '_';
    }

    private void add_highlights(List<SearchMatch> matches,
            Highlighter.HighlightPainter painter, List<Object> dest_tags) {
        if (matches == null || matches.isEmpty()) {
            return;
        }
        Highlighter highlighter = code_area.getHighlighter();
        for (SearchMatch match : matches) {
            try {
                Object tag = highlighter.addHighlight(match.start, match.end, painter);
                dest_tags.add(tag);
            } catch (BadLocationException e) {
            }
        }
    }

    private void clear_highlight_tags(List<Object> tags) {
        if (tags == null || tags.isEmpty()) {
            return;
        }
        Highlighter highlighter = code_area.getHighlighter();
        for (Object tag : tags) {
            if (tag == null) {
                continue;
            }
            highlighter.removeHighlight(tag);
        }
        tags.clear();
    }

    synchronized private boolean check_and_set_busy(boolean v) {
        if (v && busy) {
            return false;
        }
        busy = v;
        return true;
    }
}
