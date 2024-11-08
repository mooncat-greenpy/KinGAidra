package kingaidra.decom.gui;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

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
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.KinGAidraDecomTaskService;
import kingaidra.decom.ai.Ai;
import kingaidra.decom.ai.Model;
import kingaidra.decom.ai.ModelByScript;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import resources.Icons;

public class DecomGUI extends JPanel {

    private JButton restart_btn;
    private JButton guess_btn;
    private JButton refact_btn;

    private DockingAction conf_action;
    private DockingAction refr_action;

    private Program program;
    private PluginTool plugin;
    private KinGAidraDecomTaskService srv;
    private GhidraUtil ghidra;
    private Ai ai;
    private GuessGUI ggui;
    private RefactorGUI rgui;

    private boolean busy;

    public DecomGUI(ComponentProvider provider, Tool dockingTool, Program program, Plugin plugin,
            String owner, KinGAidraDecomTaskService srv) {
        super();
        this.program = program;
        this.plugin = plugin.getTool();
        this.srv = srv;
        check_and_set_busy(false);
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        buildPanel();

        setVisible(true);
    }

    // Customize GUI
    private void buildPanel() {
        ghidra = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
        ai = new Ai(plugin, program, srv);
        ggui = new GuessGUI(ghidra, ai,
                new Model[] {new ModelByScript("Sample", "sample.py"),
                        new ModelByScript("None", "none.py"),
                        new ModelByScript("ChatGPTLike", "chatgptlike.py")});
        rgui = new RefactorGUI(ghidra);

        JPanel btn_panel = new JPanel();
        JLabel info_label = new JLabel();
        info_label.setPreferredSize(new Dimension(0, 40));
        add(info_label);
        restart_btn = new JButton("Clean");
        guess_btn = new JButton("Guess");
        refact_btn = new JButton("Refact");
        refact_btn.setEnabled(false);
        Dimension button_size = new Dimension(100, 40);

        restart_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!check_and_set_busy(true)) {
                    return;
                }
                restart_btn.setEnabled(false);
                guess_btn.setEnabled(false);
                refact_btn.setEnabled(false);
                info_label.setText("Working ...");
                try {
                    rgui.reset();
                } finally {
                    info_label.setText("Finished!");
                    restart_btn.setEnabled(true);
                    guess_btn.setEnabled(true);
                    refact_btn.setEnabled(false);
                    check_and_set_busy(false);
                    validate();
                }
            }
        });
        restart_btn.setPreferredSize(button_size);
        btn_panel.add(restart_btn);

        guess_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!check_and_set_busy(true)) {
                    return;
                }
                restart_btn.setEnabled(false);
                guess_btn.setEnabled(false);
                refact_btn.setEnabled(false);
                info_label.setText("Working ...");
                // TODO: Need to be fixed
                Thread th = new Thread(() -> {
                    try {
                        Address addr = ghidra.get_current_addr();
                        if (addr != null) {
                            DecomDiff[] diffs = ggui.run_guess(addr);

                            for (DecomDiff d : diffs) {
                                rgui.add_tab(d.get_model().get_name(), d);
                            }
                        }
                    } finally {
                        info_label.setText("Finished!");
                        restart_btn.setEnabled(true);
                        guess_btn.setEnabled(true);
                        refact_btn.setEnabled(true);
                        check_and_set_busy(false);
                        validate();
                    }
                });
                th.start();

                validate();
            }
        });
        guess_btn.setPreferredSize(button_size);
        btn_panel.add(guess_btn);

        refact_btn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!check_and_set_busy(true)) {
                    return;
                }
                restart_btn.setEnabled(false);
                guess_btn.setEnabled(false);
                refact_btn.setEnabled(false);
                info_label.setText("Working ...");
                try {
                    rgui.run_refact();
                } finally {
                    info_label.setText("Finished!");
                    restart_btn.setEnabled(true);
                    guess_btn.setEnabled(true);
                    refact_btn.setEnabled(false);
                    check_and_set_busy(false);
                    validate();
                }
            }
        });
        refact_btn.setPreferredSize(button_size);
        btn_panel.add(refact_btn);

        add(btn_panel);
        add(rgui);
    }

    // TODO: Customize actions
    public void initActions(ComponentProvider provider, Tool dockingTool) {
        new ActionBuilder("Refactoring using AI", provider.getName())
                .withContext(ProgramLocationActionContext.class).enabledWhen(context -> {
                    var func = context.getProgram().getFunctionManager()
                            .getFunctionContaining(context.getAddress());
                    return func != null;
                }).onAction(context -> {
                    var func = context.getProgram().getFunctionManager()
                            .getFunctionContaining(context.getAddress());
                    if (func == null) {
                        Msg.showError(provider, null, "Not found", "Not found.");
                        return;
                    }

                    provider.setVisible(true);
                    provider.toFront();

                    guess_btn.doClick();
                }).popupMenuPath(new String[] {"Refactoring using AI"}).popupMenuGroup("KinGAidra")
                .buildAndInstall(plugin);

        conf_action = new DockingAction("Configure", provider.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                JPanel p = new JPanel();
                if (ggui != null) {
                    p.add(ggui);
                }

                JOptionPane.showMessageDialog(null, p, "Configure", JOptionPane.PLAIN_MESSAGE);
            }
        };
        conf_action.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, null));
        conf_action.setEnabled(true);
        conf_action.markHelpUnnecessary();
        dockingTool.addLocalAction(provider, conf_action);

        refr_action = new DockingAction("Refresh", provider.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                setVisible(true);
            }
        };
        refr_action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
        refr_action.setEnabled(true);
        refr_action.markHelpUnnecessary();
        dockingTool.addLocalAction(provider, refr_action);
    }

    synchronized private boolean check_and_set_busy(boolean v) {
        if (v && busy) {
            return false;
        }
        busy = v;
        return true;
    }
}
