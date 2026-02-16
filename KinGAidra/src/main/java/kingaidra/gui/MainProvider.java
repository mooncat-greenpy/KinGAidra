package kingaidra.gui;

import java.util.LinkedList;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.ComponentProvider;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;
import kingaidra.KinGAidraPlugin;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerGhidraProgram;
import kingaidra.ai.model.ModelConf;
import kingaidra.ai.model.ModelConfMultiple;
import kingaidra.ai.model.ModelConfSingle;
import kingaidra.ai.model.ModelScriptUpdater;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.chat.gui.ChatGUI;
import kingaidra.decom.gui.DecomGUI;
import kingaidra.decom.gui.LlmDecompileGUI;
import kingaidra.ghidra.ChatModelPreferences;
import kingaidra.ghidra.PromptConf;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.keyfunc.gui.KeyFuncGUI;
import kingaidra.log.Logger;
import kingaidra.mcp.McpControlGui;
import resources.Icons;

public class MainProvider extends ComponentProvider {

    private JTabbedPane main_panel;
    private ChatGUI chat_panel;
    private DecomGUI decom_panel;
    private LlmDecompileGUI llm_decom_panel;
    private KeyFuncGUI keyfunc_panel;
    private McpControlGui mcp_control_gui;

    public MainProvider(Program program, Plugin plugin, String owner,
            KinGAidraChatTaskService srv, Logger logger, PromptConf conf) {
        super(plugin.getTool(), owner, owner);

        if (plugin instanceof KinGAidraPlugin) {
            this.mcp_control_gui = new McpControlGui(this, this.dockingTool, (KinGAidraPlugin) plugin);
        }

        GhidraUtil ghidra = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerGhidraProgram(program, ghidra);
        Ai ai = new Ai(plugin.getTool(), program, ghidra, container, srv, conf);

        ModelConfSingle chat_model_conf = new ModelConfSingle("Chat and others",
                new ChatModelPreferences("chat"));
        ModelConfMultiple refactor_model_conf = new ModelConfMultiple("Decom",
                new ChatModelPreferences("refactor"));

        main_panel = new JTabbedPane();

        chat_panel = new ChatGUI(this, this.dockingTool, program, plugin, owner, srv, ghidra, chat_model_conf, conf, container, ai, logger);
        main_panel.add("Chat", chat_panel);

        decom_panel = new DecomGUI(this, this.dockingTool, program, plugin, owner, srv, ghidra, refactor_model_conf, conf, ai, logger);
        main_panel.add("Decom", decom_panel);

        llm_decom_panel = new LlmDecompileGUI(this, this.dockingTool, program, plugin, owner, ghidra, container, chat_model_conf, conf, ai, logger);
        main_panel.add("DecomView", llm_decom_panel);

        // Currently considering a feature to identify areas that should be prioritized for analysis in binary analysis
        keyfunc_panel = new KeyFuncGUI(this, this.dockingTool, program, plugin, owner, srv, ghidra, chat_model_conf, conf, ai, logger);
        main_panel.add("KeyFunc", keyfunc_panel);

        setVisible(true);

        createActions(chat_model_conf, refactor_model_conf, conf, logger, program);

        ModelScriptUpdater updater = new ModelScriptUpdater();
        updater.update_scripts();
    }

    public void change_tab(String name) {
        int idx = main_panel.indexOfTab(name);
        if (idx < 0) {
            return;
        }
        main_panel.setSelectedIndex(idx);
    }

    public void createActions(ModelConf chat_model_conf, ModelConf refactor_model_conf, PromptConf conf, Logger logger, Program program) {
        if (keyfunc_panel != null) {
            keyfunc_panel.initActions(this, dockingTool);
        }
        if (decom_panel != null) {
            decom_panel.initActions(this, dockingTool);
        }
        if (llm_decom_panel != null) {
            llm_decom_panel.initActions(this, dockingTool);
        }
        if (chat_panel != null) {
            chat_panel.initActions(this, dockingTool);
        }

        DockingAction conf_action = new DockingAction("Configure", this.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                JPanel p = new JPanel();
                p.setLayout(new BoxLayout(p, BoxLayout.X_AXIS));

                List<ModelConf> model_conf_list = new LinkedList<>();
                model_conf_list.add(chat_model_conf);
                model_conf_list.add(refactor_model_conf);
                ModelConfGUI conf_panel = new ModelConfGUI(model_conf_list, logger);
                p.add(conf_panel);

                JOptionPane.showMessageDialog(null, p, "Configure", JOptionPane.PLAIN_MESSAGE);
            }
        };
        conf_action.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, null));
        conf_action.setEnabled(true);
        conf_action.markHelpUnnecessary();
        dockingTool.addLocalAction(this, conf_action);
        if (mcp_control_gui != null) {
            mcp_control_gui.create_action(program);
        }
    }

    @Override
    public JComponent getComponent() {
        return main_panel;
    }

    public void location_changed(ProgramLocation loc) {
        if (llm_decom_panel != null) {
            llm_decom_panel.update_location(loc);
        }
    }
}
