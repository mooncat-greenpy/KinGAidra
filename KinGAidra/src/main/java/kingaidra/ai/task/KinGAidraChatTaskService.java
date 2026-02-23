package kingaidra.ai.task;

import ghidra.framework.plugintool.ServiceInfo;
import kingaidra.KinGAidraPlugin;
import kingaidra.ai.convo.Conversation;

//@formatter:off
@ServiceInfo (
	defaultProvider=KinGAidraPlugin.class,
	description="service"
)
//@formatter:on
public interface KinGAidraChatTaskService {
    public void add_task(String key, TaskType type, Conversation convo);

    public void commit_task(String key, String msg);

    public void commit_task_error(String key, String err_msg);

    public Conversation get_task(String key);

    public TaskType get_task_type(String key);

    public TaskStatus get_task_status(String key);

    public Conversation pop_task(String key);

    public boolean start_mcp_server();

    public boolean stop_mcp_server();

    public boolean is_mcp_running();

    public String ensure_mcp_server_url();

    public void publish_mcp_server_url(String host, int port);
}
