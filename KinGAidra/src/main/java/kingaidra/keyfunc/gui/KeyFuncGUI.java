package kingaidra.keyfunc.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.AbstractMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.Tool;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelByScript;
import kingaidra.ai.model.ModelConf;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.decom.extractor.JsonExtractor;
import kingaidra.keyfunc.Guess;
import kingaidra.keyfunc.extractor.FunctionReasonJson;
import kingaidra.keyfunc.extractor.StringListJson;
import kingaidra.log.Logger;
import kingaidra.ghidra.ChatModelPreferences;
import kingaidra.ghidra.PromptConf;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.gui.MainProvider;

public class KeyFuncGUI extends JPanel {

    private Program program;
    private PluginTool plugin;
    private KinGAidraChatTaskService srv;
    private GhidraUtil ghidra;
    private ModelConf model_conf;
    private PromptConf conf;
    private Ai ai;
    private ConversationContainer container;
    private Logger logger;

    private JButton guess_btn;
    private JButton load_history_btn;
    private JLabel info_label;
    private StringTableGUI string_table;

    private boolean busy;

    public KeyFuncGUI(MainProvider provider, Tool dockingTool, Program program, Plugin plugin,
            String owner, KinGAidraChatTaskService srv, GhidraUtil ghidra, ModelConf model_conf,
            PromptConf conf, Ai ai, ConversationContainer container, Logger logger) {
        super();
        this.program = program;
        this.plugin = plugin.getTool();
        this.srv = srv;
        this.ghidra = ghidra;
        this.model_conf = model_conf;
        this.conf = conf;
        this.ai = ai;
        this.container = container;
        this.logger = logger;
        setLayout(new BorderLayout());

        init_panel();
        load_saved_results();

        setVisible(true);
    }

    private void init_panel() {
        GhidraPreferences<Model> old_pref = new ChatModelPreferences("keyfunc");
        old_pref.remove_all();
        Guess guess = new Guess(ghidra, ai, model_conf, conf);

        Model chatgptlike_model =
                new ModelByScript("ChatGPTLike", "kingaidra_chat.py", true);
        if (!guess.get_model_conf().exist_model(chatgptlike_model.get_name())) {
            guess.get_model_conf().add_model(chatgptlike_model.get_name(), chatgptlike_model.get_script());
            guess.get_model_conf().set_model_status(chatgptlike_model.get_name(), chatgptlike_model.get_active());
        }

        guess_btn = new JButton("Guess");
        load_history_btn = new JButton("Load History");
        info_label = new JLabel("");
        Dimension button_size = new Dimension(100, 30);
        guess_btn.setPreferredSize(button_size);
        load_history_btn.setPreferredSize(new Dimension(130, 30));
        guess_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!check_and_set_busy(true)) {
                    return;
                }
                logger.append_message("Start: KeyFunc");
                set_controls_enabled(false);
                info_label.setText("Working ...");
                Thread th = new Thread(() -> {
                    try {
                        Map.Entry<Function, String>[] funcs = guess.guess_by_chat_histories(ghidra.get_current_addr());
                        string_table.update(program, funcs);
                        info_label.setText("Finished: " + funcs.length);
                    } finally {
                        set_controls_enabled(true);
                        check_and_set_busy(false);
                        logger.append_message("Finish: KeyFunc");
                        validate();
                    }
                });
                th.start();
                validate();
            }
        });
        load_history_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                load_saved_results();
            }
        });

        JPanel input_panel = new JPanel();
        input_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        input_panel.add(guess_btn);
        input_panel.add(load_history_btn);
        input_panel.add(info_label);
        add(input_panel, BorderLayout.NORTH);
        string_table = new StringTableGUI(plugin, program);
        add(string_table, BorderLayout.CENTER);
    }

    private void load_saved_results() {
        if (!check_and_set_busy(true)) {
            return;
        }
        set_controls_enabled(false);
        info_label.setText("Loading ...");
        Thread th = new Thread(() -> {
            try {
                Map.Entry<Function, String>[] funcs = get_saved_results_from_history();
                string_table.update(program, funcs);
                info_label.setText("Loaded: " + funcs.length);
            } finally {
                set_controls_enabled(true);
                check_and_set_busy(false);
                validate();
            }
        });
        th.start();
    }

    private void set_controls_enabled(boolean enabled) {
        guess_btn.setEnabled(enabled);
        load_history_btn.setEnabled(enabled);
    }

    private Map.Entry<Function, String>[] get_saved_results_from_history() {
        UUID[] ids = container.get_ids();

        Map<Long, Map.Entry<Function, String>> merged = new LinkedHashMap<>();
        for (UUID id : ids) {
            Conversation convo = container.get_convo(id);
            if (convo == null || convo.get_type() != ConversationType.SYSTEM_KEYFUNC
                    || convo.get_msgs_len() == 0) {
                continue;
            }
            String output = convo.get_msg(convo.get_msgs_len() - 1);
            JsonExtractor<FunctionReasonJson> func_extractor =
                    new JsonExtractor<>(output, FunctionReasonJson.class);
            FunctionReasonJson func_reason_json = func_extractor.get_data();
            if (func_reason_json != null) {
                for (FunctionReasonJson.FunctionReasonItem item : func_reason_json.get_funcs()) {
                    for (Function func : ghidra.get_func(item.get_name())) {
                        merge_reason(merged, func, item.get_reason(), " / ");
                    }
                }
                continue;
            }

            JsonExtractor<StringListJson> string_extractor =
                    new JsonExtractor<>(output, StringListJson.class);
            StringListJson string_json = string_extractor.get_data();
            if (string_json == null) {
                continue;
            }

            Data[] data_list = ghidra.get_strings();
            for (String str : string_json.get_strings()) {
                for (Data data : data_list) {
                    if (!data.getDefaultValueRepresentation().contains(str)) {
                        continue;
                    }
                    for (Reference ref : ghidra.get_ref_to(data.getAddress())) {
                        Function func = ghidra.get_func(ref.getFromAddress());
                        if (func != null) {
                            merge_reason(merged, func, "`" + str + "`", ", ");
                        }
                    }
                }
            }
        }
        return merged.values().toArray(new Map.Entry[]{});
    }

    private void merge_reason(
            Map<Long, Map.Entry<Function, String>> merged, Function func, String reason, String delimiter) {
        long key = func.getEntryPoint().getOffset();
        Map.Entry<Function, String> prev = merged.get(key);
        if (prev == null) {
            merged.put(key, new AbstractMap.SimpleEntry<>(func, reason));
            return;
        }
        merged.put(key, new AbstractMap.SimpleEntry<>(func, prev.getValue() + delimiter + reason));
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
