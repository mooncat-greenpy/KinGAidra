package kingaidra.gui;

import javax.swing.*;

import docking.ComponentProvider;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerDummy;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.chat.gui.ChatGUI;
import kingaidra.decom.gui.DecomGUI;
import kingaidra.keyfunc.gui.KeyFuncGUI;

public class MainProvider extends ComponentProvider {

    private JTabbedPane main_panel;
    private ChatGUI chat_panel;
    private DecomGUI decom_panel;
    private KeyFuncGUI keyfunc_panel;

    public MainProvider(Program program, Plugin plugin, String owner,
            KinGAidraChatTaskService srv) {
        super(plugin.getTool(), owner, owner);
        ConversationContainer container = new ConversationContainerDummy();

        main_panel = new JTabbedPane();

        chat_panel = new ChatGUI(this, this.dockingTool, program, plugin, owner, srv, container);
        main_panel.add("Chat", chat_panel);

        decom_panel = new DecomGUI(this, this.dockingTool, program, plugin, owner, srv, container);
        main_panel.add("Decom", decom_panel);

        // Currently considering a feature to identify areas that should be prioritized for analysis in binary analysis
        keyfunc_panel = new KeyFuncGUI(this, this.dockingTool, program, plugin, owner, srv, container);
        main_panel.add("KeyFunc", keyfunc_panel);

        setVisible(true);

        createActions();
    }

    public void change_tab(String name) {
        int idx = main_panel.indexOfTab(name);
        if (idx < 0) {
            return;
        }
        main_panel.setSelectedIndex(idx);
    }

    public void createActions() {
        if (keyfunc_panel != null) {
            keyfunc_panel.initActions(this, dockingTool);
        }
        if (decom_panel != null) {
            decom_panel.initActions(this, dockingTool);
        }
        if (chat_panel != null) {
            chat_panel.initActions(this, dockingTool);
        }
    }

    @Override
    public JComponent getComponent() {
        return main_panel;
    }
}
