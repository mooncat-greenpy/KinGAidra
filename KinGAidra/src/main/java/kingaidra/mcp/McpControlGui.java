package kingaidra.mcp;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.Window;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.Tool;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.program.model.listing.Program;
import kingaidra.KinGAidraPlugin;
import resources.Icons;

public class McpControlGui {
    private final ComponentProvider provider;
    private final Tool docking_tool;
    private final KinGAidraPlugin plugin;
    private JDialog dialog;

    public McpControlGui(ComponentProvider provider, Tool docking_tool, KinGAidraPlugin plugin) {
        this.provider = provider;
        this.docking_tool = docking_tool;
        this.plugin = plugin;
    }

    public void create_action(Program program) {
        DockingAction mcp_action = new DockingAction("MCP Control", provider.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                show_control_dialog(program);
            }
        };
        mcp_action.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, null));
        mcp_action.setEnabled(true);
        mcp_action.markHelpUnnecessary();
        docking_tool.addLocalAction(provider, mcp_action);
    }

    private void show_control_dialog(Program program) {
        if (dialog != null && dialog.isShowing()) {
            dialog.toFront();
            return;
        }

        Window owner = SwingUtilities.getWindowAncestor(provider.getComponent());
        dialog = new JDialog(owner, "MCP Control", Dialog.ModalityType.MODELESS);
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosed(WindowEvent e) {
                dialog = null;
            }
        });
        dialog.setContentPane(create_control_panel(program));
        dialog.pack();
        dialog.setLocationRelativeTo(provider.getComponent());
        dialog.setVisible(true);
    }

    private JPanel create_control_panel(Program program) {
        JPanel root = new JPanel(new BorderLayout());
        JPanel button_panel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton start_button = new JButton("Start");
        JButton stop_button = new JButton("Stop");
        start_button.addActionListener(e -> on_start(program));
        stop_button.addActionListener(e -> on_stop());
        button_panel.add(start_button);
        button_panel.add(stop_button);
        root.add(button_panel, BorderLayout.CENTER);
        return root;
    }

    private void on_start(Program program) {
        if (!plugin.start_mcp_server(program)) {
            show_info("MCP Start", "MCP server is already running.");
        }
    }

    private void on_stop() {
        if (!plugin.stop_mcp_server()) {
            show_info("MCP Stop", "MCP server is not running.");
        }
    }

    private void show_info(String title, String message) {
        JOptionPane.showMessageDialog(dialog, message, title, JOptionPane.INFORMATION_MESSAGE);
    }
}
