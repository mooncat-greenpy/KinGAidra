package kingaidra.gui;

import javax.swing.*;

import docking.ComponentProvider;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import kingaidra.decom.KinGAidraDecomTaskService;
import kingaidra.decom.gui.DecomGUI;

public class MainProvider extends ComponentProvider {

    private DecomGUI panel;

    public MainProvider(Program program, Plugin plugin, String owner,
            KinGAidraDecomTaskService srv) {
        super(plugin.getTool(), owner, owner);

        panel = new DecomGUI(this, this.dockingTool, program, plugin, owner, srv);
        setVisible(true);
    }

    // TODO: Customize actions
    public void createActions() {
        panel.initActions(this, dockingTool);
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }
}
