package kingaidra;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.action.builder.ActionBuilder;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import kingaidra.decom.DecomDiff;
import kingaidra.decom.KinGAidraDecomTaskService;
import kingaidra.decom.ai.Ai;
import kingaidra.decom.ai.Model;
import kingaidra.decom.ai.ModelByScript;
import kingaidra.decom.gui.GuessGUI;
import kingaidra.decom.gui.RefactorGUI;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import resources.Icons;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = ExamplesPluginPackage.NAME,
    category = PluginCategoryNames.EXAMPLES,
    shortDescription = "Plugin short description goes here.",
    description = "Plugin long description goes here.",
    servicesProvided = { KinGAidraDecomTaskService.class },
    servicesRequired = {}
)
//@formatter:on
public class KinGAidraPlugin extends ProgramPlugin implements KinGAidraDecomTaskService {

    MyProvider provider;

    /**
     * Plugin constructor.
     * 
     * @param tool The plugin tool that this plugin is added to.
     */
    public KinGAidraPlugin(PluginTool tool) {
        super(tool);

        // TODO: Customize provider (or remove if a provider is not desired)
        String pluginName = getName();
        provider = new MyProvider(this, pluginName, this);

        // TODO: Customize help (or remove if help is not desired)
        String topicName = this.getClass().getPackage().getName();
        String anchorName = "HelpAnchor";
        provider.setHelpLocation(new HelpLocation(topicName, anchorName));

        diff_map = new HashMap<>();
    }

    @Override
    public void init() {
        super.init();

        // TODO: Acquire services if necessary
    }

    private Map<String, DecomDiff> diff_map;

    @Override
    public void add_task(String key, DecomDiff diff) {
        diff_map.put(key, diff);
    }

    @Override
    public void commit_task(String key, String func_name, Map<String, String> params,
            Map<String, String> vars) {
        DecomDiff diff = diff_map.get(key);
        diff.set_name(func_name);
        for (String p_key : params.keySet()) {
            diff.set_param_new_name(p_key, params.get(p_key));
        }
        for (String v_key : vars.keySet()) {
            diff.set_var_new_name(v_key, vars.get(v_key));
        }
        diff_map.put(key, diff);
    }

    @Override
    public DecomDiff get_task(String key) {
        return diff_map.get(key);
    }

    @Override
    public DecomDiff pop_task(String key) {
        DecomDiff diff = get_task(key);
        diff_map.remove(key);
        return diff;
    }

    // TODO: If provider is desired, it is recommended to move it to its own file
    private static class MyProvider extends ComponentProvider {

        private JPanel panel;
        private JButton restart_btn;
        private JButton guess_btn;
        private JButton refact_btn;

        private DockingAction conf_action;
        private DockingAction refr_action;

        private PluginTool plugin;
        private KinGAidraDecomTaskService srv;
        private GhidraUtil ghidra;
        private Ai ai;
        private GuessGUI ggui;
        private RefactorGUI rgui;

        public MyProvider(Plugin plugin, String owner, KinGAidraDecomTaskService srv) {
            super(plugin.getTool(), owner, owner);
            this.plugin = plugin.getTool();
            this.srv = srv;
            panel = new JPanel();
            panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
            init();
            setVisible(true);
            createActions();
        }

        private void init() {
            if (ghidra != null && ggui != null && rgui != null) {
                return;
            }
            ProgramManager service = getTool().getService(ProgramManager.class);
            if (service == null) {
                return;
            }
            Program program = service.getCurrentProgram();
            if (program == null) {
                return;
            }
            ghidra = new GhidraUtilImpl(program, TaskMonitor.DUMMY);
            ai = new Ai(plugin, program, srv);
            ggui = new GuessGUI(ghidra, ai, new Model[] {new ModelByScript("Sample", "sample.py"),
                    new ModelByScript("None", "none.py"), new ModelByScript("ChatGPTLike", "chatgptlike.py")});
            rgui = new RefactorGUI(ghidra);

            buildPanel();

            panel.add(rgui);
            panel.validate();
        }

        // Customize GUI
        private void buildPanel() {
            JPanel btn_panel = new JPanel();
            restart_btn = new JButton("Clean");
            guess_btn = new JButton("Guess");
            refact_btn = new JButton("Refact");
            refact_btn.setEnabled(false);
            Dimension button_size = new Dimension(100, 40);

            restart_btn.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    refact_btn.setEnabled(false);
                    rgui.reset();
                    panel.validate();
                }
            });
            restart_btn.setPreferredSize(button_size);
            btn_panel.add(restart_btn);

            guess_btn.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    DecomDiff[] diffs = ggui.run_guess(ghidra.get_current_addr());

                    for (DecomDiff d : diffs) {
                        rgui.add_tab(d.get_model().get_name(), d);
                    }
                    refact_btn.setEnabled(true);
                    panel.validate();
                }
            });
            guess_btn.setPreferredSize(button_size);
            btn_panel.add(guess_btn);

            refact_btn.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    rgui.run_refact();
                    refact_btn.setEnabled(false);
                    panel.validate();
                }
            });
            refact_btn.setPreferredSize(button_size);
            btn_panel.add(refact_btn);

            panel.add(btn_panel);
        }

        // TODO: Customize actions
        private void createActions() {
            new ActionBuilder("Refactoring using AI", this.getName())
                    .withContext(ProgramLocationActionContext.class).enabledWhen(context -> {
                        var func = context.getProgram().getFunctionManager()
                                .getFunctionContaining(context.getAddress());
                        return func != null;
                    }).onAction(context -> {
                        var func = context.getProgram().getFunctionManager()
                                .getFunctionContaining(context.getAddress());
                        if (func == null) {
                            Msg.showError(this, null, "Not found", "Not found.");
                            return;
                        }
                        init();

                        this.setVisible(true);
                        this.toFront();
                        guess_btn.doClick();
                    }).popupMenuPath(new String[] {"Refactoring using AI"})
                    .popupMenuGroup("KinGAidra").buildAndInstall(plugin);

            conf_action = new DockingAction("Configure", getName()) {
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
            dockingTool.addLocalAction(this, conf_action);

            refr_action = new DockingAction("Refresh", getName()) {
                @Override
                public void actionPerformed(ActionContext context) {
                    init();
                }
            };
            refr_action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
            refr_action.setEnabled(true);
            refr_action.markHelpUnnecessary();
            dockingTool.addLocalAction(this, refr_action);
        }

        @Override
        public JComponent getComponent() {
            return panel;
        }
    }
}
