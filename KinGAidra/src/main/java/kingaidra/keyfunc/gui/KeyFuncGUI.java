package kingaidra.keyfunc.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.Tool;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerDummy;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelByScript;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.keyfunc.Guess;
import kingaidra.ghidra.ChatModelPreferences;
import kingaidra.ghidra.GhidraPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.gui.MainProvider;
import resources.Icons;

public class KeyFuncGUI extends JPanel {

    private Program program;
    private PluginTool plugin;
    private KinGAidraChatTaskService srv;
    private GhidraUtil ghidra;

    private DockingAction conf_action;

    private JButton guess_btn;
    private GuessGUI ggui;
    private StringTableGUI string_table;

    public KeyFuncGUI(MainProvider provider, Tool dockingTool, Program program, Plugin plugin,
            String owner, KinGAidraChatTaskService srv) {
        super();
        this.program = program;
        this.plugin = plugin.getTool();
        this.srv = srv;
        setLayout(new BorderLayout());

        init_panel();

        setVisible(true);
    }

    private void init_panel() {
        GhidraPreferences<Model> pref = new ChatModelPreferences("keyfunc");
        ghidra = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerDummy();
        Ai ai = new Ai(plugin, program, ghidra, container, srv);

        Guess guess = new Guess(ghidra, ai, pref);
        ggui = new GuessGUI(guess);

        guess_btn = new JButton("Guess");
        Dimension button_size = new Dimension(100, 30);
        guess_btn.setPreferredSize(button_size);
        guess_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Data[] data = guess.guess_string_data();
                string_table.update(program, data, ghidra);
            }
        });

        JPanel input_panel = new JPanel();
		input_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        input_panel.add(guess_btn);
        add(input_panel, BorderLayout.NORTH);
        string_table = new StringTableGUI(plugin, program, ghidra);
        add(string_table, BorderLayout.CENTER);
    }

    public void initActions(MainProvider provider, Tool dockingTool) {
        conf_action = new DockingAction("KeyFuncConfigure", provider.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                JPanel p = new JPanel();
                if (ggui != null) {
                    p.add(ggui);
                }

                JOptionPane.showMessageDialog(null, p, "KeyFuncConfigure", JOptionPane.PLAIN_MESSAGE);
            }
        };

        conf_action.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, null));
        conf_action.setEnabled(true);
        conf_action.markHelpUnnecessary();
        dockingTool.addLocalAction(provider, conf_action);
    }
}
