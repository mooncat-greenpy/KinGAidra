package kingaidra.decom.gui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import docking.Tool;
import docking.action.builder.ActionBuilder;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
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
    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private Program program;
    private PluginTool plugin;
    private GhidraUtil ghidra;
    private ConversationContainer container;
    private Logger logger;
    private LlmDecompile llm_decompile;
    private ConcurrentMap<Address, String> decompile_results;
    private ConcurrentMap<Address, String> decompile_updated;

    private JLabel info_label;
    private JLabel func_label;
    private JButton regen_btn;
    private JButton load_btn;
    private JButton copy_btn;
    private JComboBox<FunctionSelectionItem> function_selector;
    private RSyntaxTextArea code_area;
    private Address current_func_entry;
    private boolean updating_function_selector;

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

    private static class FunctionSelectionItem {
        private Address entry;
        private String label;

        FunctionSelectionItem(Address entry, String label) {
            this.entry = entry;
            this.label = label;
        }

        public Address get_entry() {
            return entry;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    public LlmDecompileGUI(MainProvider provider, Tool dockingTool, Program program, Plugin plugin,
            String owner, GhidraUtil ghidra, ConversationContainer container, ModelConf model_conf, PromptConf conf,
            Ai ai, Logger logger) {
        super();
        this.program = program;
        this.plugin = plugin.getTool();
        this.ghidra = ghidra;
        this.container = container;
        this.logger = logger;
        this.llm_decompile = new LlmDecompile(ai, ghidra, model_conf, conf);
        this.decompile_results = new ConcurrentHashMap<>();
        this.decompile_updated = new ConcurrentHashMap<>();
        this.current_func_entry = null;
        this.updating_function_selector = false;
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
        load_btn = new JButton("Load Saved");
        copy_btn = new JButton("Copy");
        info_label = new JLabel("");
        func_label = new JLabel("Function: (none)");
        function_selector = new JComboBox<>();
        function_selector.setPrototypeDisplayValue(
                new FunctionSelectionItem(null, "function_name @ 0x00000000 (yyyy-MM-dd HH:mm:ss)"));
        function_selector.setEnabled(false);

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
        load_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                run_load_saved_results();
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
                if (item == null || item.get_entry() == null) {
                    return;
                }
                show_code_for_function(item.get_entry(), false);
            }
        });
        button_panel.add(regen_btn);
        button_panel.add(load_btn);
        button_panel.add(copy_btn);
        button_panel.add(info_label);

        JPanel function_selector_panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        function_selector_panel.add(new JLabel("Saved Function:"));
        function_selector_panel.add(function_selector);

        header.add(button_panel);
        header.add(function_selector_panel);
        header.add(func_label);
        add(header, BorderLayout.NORTH);

        code_area = new RSyntaxTextArea();
        code_area.setEditable(false);
        code_area.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_C);
        code_area.setCodeFoldingEnabled(true);
        code_area.setText(MSG_NO_FUNCTION);

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
            func_label.setText("Function: (none)");
            set_code(MSG_NO_FUNCTION);
            return;
        }
        Function func = program.getFunctionManager().getFunctionContaining(loc.getAddress());
        if (func == null) {
            current_func_entry = null;
            func_label.setText("Function: (none)");
            set_code(MSG_NO_FUNCTION);
            return;
        }

        Address entry = func.getEntryPoint();
        current_func_entry = entry;
        select_function_entry(entry);
        show_code_for_function(entry, true);
    }

    private Function get_current_function() {
        Address addr = ghidra.get_current_addr();
        if (addr == null) {
            return null;
        }
        return program.getFunctionManager().getFunctionContaining(addr);
    }

    private void run_llm_decompile(Address func_entry) {
        if (func_entry == null) {
            return;
        }
        Function func = program.getFunctionManager().getFunctionAt(func_entry);
        if (func != null) {
            current_func_entry = func_entry;
            func_label.setText(String.format("Function: %s @ %s", func.getName(), func_entry));
        }
        if (!check_and_set_busy(true)) {
            logger.append_message("Another process running");
            return;
        }
        regen_btn.setEnabled(false);
        info_label.setText("Working ...");

        SwingWorker<String, Void> worker = new SwingWorker<>() {
            @Override
            protected String doInBackground() {
                return llm_decompile.guess(func_entry);
            }

            @Override
            protected void done() {
                try {
                    String code = get();
                    if (code != null && !code.isEmpty()) {
                        decompile_results.put(func_entry, code);
                        decompile_updated.put(func_entry, LocalDateTime.now().format(DATE_FORMAT));
                        refresh_function_selector(func_entry);
                        info_label.setText("Finished!");
                    } else {
                        info_label.setText("Failed!");
                    }
                } catch (Exception e) {
                    info_label.setText("Failed!");
                } finally {
                    if (current_func_entry != null && current_func_entry.equals(func_entry)) {
                        show_code_for_function(func_entry, true);
                    }
                    regen_btn.setEnabled(true);
                    load_btn.setEnabled(true);
                    function_selector.setEnabled(function_selector.getItemCount() > 0);
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
        regen_btn.setEnabled(false);
        load_btn.setEnabled(false);
        function_selector.setEnabled(false);
        info_label.setText("Loading ...");
        Address selected_entry = get_selected_function_entry();

        SwingWorker<List<SavedResult>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<SavedResult> doInBackground() {
                return get_saved_results();
            }

            @Override
            protected void done() {
                int merged = 0;
                try {
                    List<SavedResult> saved = get();
                    merged = merge_saved_results(saved);
                    refresh_function_selector(selected_entry);
                    if (current_func_entry != null) {
                        show_code_for_function(current_func_entry, true);
                    }
                    info_label.setText(merged > 0 ? ("Loaded " + merged + " result(s)") : "No saved result");
                } catch (Exception e) {
                    info_label.setText("Load failed");
                } finally {
                    regen_btn.setEnabled(true);
                    load_btn.setEnabled(true);
                    function_selector.setEnabled(function_selector.getItemCount() > 0);
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

        Map<Long, SavedResult> latest_by_entry = new HashMap<>();
        for (UUID id : ids) {
            Conversation convo = container.get_convo(id);
            if (!is_llm_decompile_conversation(convo)) {
                continue;
            }

            Address entry = get_entry_from_conversation(convo);
            if (entry == null) {
                continue;
            }

            String code = get_code_from_conversation(convo);
            if (code == null || code.isEmpty()) {
                continue;
            }

            String updated = convo.get_updated();
            SavedResult candidate = new SavedResult(entry, code, updated);
            SavedResult previous = latest_by_entry.get(entry.getOffset());
            if (should_replace_saved_result(candidate, previous)) {
                latest_by_entry.put(entry.getOffset(), candidate);
            }
        }

        result_list.addAll(latest_by_entry.values());
        return result_list;
    }

    private boolean is_llm_decompile_conversation(Conversation convo) {
        return convo != null && convo.get_type() == ConversationType.SYSTEM_DECOMPILE_VIEW;
    }

    private boolean should_replace_saved_result(SavedResult incoming, SavedResult current) {
        if (incoming == null) {
            return false;
        }
        if (current == null) {
            return true;
        }
        return is_newer(incoming.updated, current.updated);
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

    private int merge_saved_results(List<SavedResult> saved_results) {
        if (saved_results == null || saved_results.isEmpty()) {
            return 0;
        }
        int count = 0;
        for (SavedResult result : saved_results) {
            if (result == null || result.entry == null || result.code == null || result.code.isEmpty()) {
                continue;
            }
            String prev_updated = decompile_updated.get(result.entry);
            String prev_code = decompile_results.get(result.entry);
            boolean same_timestamp_but_changed =
                    result.updated != null && result.updated.equals(prev_updated)
                            && prev_code != null && !result.code.equals(prev_code);
            if (!decompile_results.containsKey(result.entry)
                    || is_newer(result.updated, prev_updated)
                    || same_timestamp_but_changed) {
                decompile_results.put(result.entry, result.code);
                decompile_updated.put(result.entry, result.updated);
                count++;
            }
        }
        return count;
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

    private void refresh_function_selector(Address selected_entry) {
        List<Address> entries = new ArrayList<>(decompile_results.keySet());
        entries.sort(new Comparator<Address>() {
            @Override
            public int compare(Address left, Address right) {
                String left_name = get_function_name(left);
                String right_name = get_function_name(right);
                int result = left_name.compareToIgnoreCase(right_name);
                if (result != 0) {
                    return result;
                }
                return left.toString().compareTo(right.toString());
            }
        });

        DefaultComboBoxModel<FunctionSelectionItem> model = new DefaultComboBoxModel<>();
        for (Address entry : entries) {
            model.addElement(new FunctionSelectionItem(entry, get_function_label(entry)));
        }

        updating_function_selector = true;
        function_selector.setModel(model);
        updating_function_selector = false;

        if (model.getSize() <= 0) {
            function_selector.setEnabled(false);
            return;
        }

        Address preferred = selected_entry != null ? selected_entry : current_func_entry;
        if (preferred != null) {
            select_function_entry(preferred);
        } else {
            function_selector.setSelectedIndex(0);
        }
        function_selector.setEnabled(!busy);
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

    private String get_function_label(Address entry) {
        String updated = decompile_updated.get(entry);
        String label = String.format("%s @ %s", get_function_name(entry), entry);
        if (updated != null && !updated.isEmpty()) {
            return label + " (" + updated + ")";
        }
        return label;
    }

    private Address get_selected_function_entry() {
        FunctionSelectionItem item = (FunctionSelectionItem) function_selector.getSelectedItem();
        if (item == null) {
            return null;
        }
        return item.get_entry();
    }

    private void select_function_entry(Address entry) {
        if (entry == null || function_selector.getItemCount() <= 0) {
            return;
        }
        updating_function_selector = true;
        for (int i = 0; i < function_selector.getItemCount(); i++) {
            FunctionSelectionItem item = function_selector.getItemAt(i);
            if (item == null || item.get_entry() == null) {
                continue;
            }
            if (item.get_entry().equals(entry)) {
                function_selector.setSelectedIndex(i);
                updating_function_selector = false;
                return;
            }
        }
        updating_function_selector = false;
    }

    private void show_code_for_function(Address entry, boolean use_no_output_placeholder) {
        if (entry == null) {
            func_label.setText("Function: (none)");
            set_code(MSG_NO_FUNCTION);
            return;
        }
        func_label.setText(String.format("Function: %s @ %s", get_function_name(entry), entry));
        String code = decompile_results.get(entry);
        if (code == null && use_no_output_placeholder) {
            set_code(MSG_NO_OUTPUT);
            return;
        }
        if (code == null) {
            return;
        }
        set_code(code);
    }

    private void set_code(String code) {
        code_area.setText(code == null ? MSG_NO_OUTPUT : code);
        code_area.setCaretPosition(0);
    }

    synchronized private boolean check_and_set_busy(boolean v) {
        if (v && busy) {
            return false;
        }
        busy = v;
        return true;
    }
}
