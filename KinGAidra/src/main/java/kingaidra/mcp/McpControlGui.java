package kingaidra.mcp;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.Window;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.net.URI;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.SwingConstants;
import javax.swing.Timer;
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
    private JLabel status_label;
    private JLabel port_label;
    private Timer status_refresh_timer;

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
        mcp_action.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_OUTGOING_EVENT_ICON, null));
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
                stop_status_refresh_timer();
                status_label = null;
                port_label = null;
                dialog = null;
            }
        });
        dialog.setContentPane(create_control_panel(program));
        dialog.pack();
        dialog.setLocationRelativeTo(provider.getComponent());
        dialog.setVisible(true);
    }

    private JPanel create_control_panel(Program program) {
        JPanel root = new JPanel(new BorderLayout(0, 8));
        JPanel status_panel = new JPanel(new BorderLayout());
        status_label = new JLabel();
        status_label.setHorizontalAlignment(SwingConstants.CENTER);
        port_label = new JLabel();
        port_label.setHorizontalAlignment(SwingConstants.CENTER);
        status_panel.add(status_label, BorderLayout.NORTH);
        status_panel.add(port_label, BorderLayout.SOUTH);

        JPanel button_panel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton start_button = new JButton("Start");
        JButton stop_button = new JButton("Stop");
        start_button.addActionListener(e -> on_start());
        stop_button.addActionListener(e -> on_stop());
        button_panel.add(start_button);
        button_panel.add(stop_button);
        root.add(status_panel, BorderLayout.NORTH);
        root.add(button_panel, BorderLayout.CENTER);

        update_status_and_port();
        start_status_refresh_timer();
        return root;
    }

    private void on_start() {
        if (!plugin.start_mcp_server()) {
            show_info("MCP Start", "MCP server is already running.");
        }
        update_status_and_port();
    }

    private void on_stop() {
        if (!plugin.stop_mcp_server()) {
            show_info("MCP Stop", "MCP server is not running.");
        }
        update_status_and_port();
    }

    private void start_status_refresh_timer() {
        stop_status_refresh_timer();
        status_refresh_timer = new Timer(300, e -> update_status_and_port());
        status_refresh_timer.start();
    }

    private void stop_status_refresh_timer() {
        if (status_refresh_timer == null) {
            return;
        }
        status_refresh_timer.stop();
        status_refresh_timer = null;
    }

    private void update_status_and_port() {
        if (status_label == null || port_label == null) {
            return;
        }

        status_label.setText("Status: " + (plugin.is_mcp_running() ? "Running" : "Stopped"));
        int port = extract_port(plugin.get_mcp_server_url());
        port_label.setText("Port: " + (port > 0 ? Integer.toString(port) : "-"));
    }

    private int extract_port(String server_url) {
        if (server_url == null || server_url.trim().isEmpty()) {
            return -1;
        }
        try {
            return URI.create(server_url).getPort();
        } catch (IllegalArgumentException e) {
            return -1;
        }
    }

    private void show_info(String title, String message) {
        JOptionPane.showMessageDialog(dialog, message, title, JOptionPane.INFORMATION_MESSAGE);
    }
}
