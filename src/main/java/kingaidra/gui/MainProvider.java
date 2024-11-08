package kingaidra.gui;

import javax.swing.*;

import docking.ComponentProvider;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import kingaidra.decom.KinGAidraDecomTaskService;
import kingaidra.decom.gui.DecomGUI;

public class MainProvider extends ComponentProvider {

    private JTabbedPane main_panel;
    private DecomGUI decom_panel;
    private JPanel yyy_panel;
    private JPanel zzz_panel;

    public MainProvider(Program program, Plugin plugin, String owner,
            KinGAidraDecomTaskService srv) {
        super(plugin.getTool(), owner, owner);

        main_panel = new JTabbedPane();
        decom_panel = new DecomGUI(this, this.dockingTool, program, plugin, owner, srv);
        main_panel.add("Decom", decom_panel);
        yyy_panel = new JPanel();
        main_panel.add("YYY", yyy_panel);
        zzz_panel = new JPanel();
        main_panel.add("ZZZ", zzz_panel);

        setVisible(true);

        createActions();
    }

    // TODO: Customize actions
    public void createActions() {
        decom_panel.initActions(this, dockingTool);
    }

    @Override
    public JComponent getComponent() {
        return main_panel;
    }
}
