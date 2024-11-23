package kingaidra.chat;

import ghidra.framework.plugintool.ServiceInfo;
import kingaidra.KinGAidraPlugin;
import kingaidra.TaskStatus;
import kingaidra.decom.ai.TaskType;

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

    public TaskType get_task_type(String key, TaskType type);

    public TaskStatus get_task_status(String key);

    public Conversation pop_task(String key);
}
