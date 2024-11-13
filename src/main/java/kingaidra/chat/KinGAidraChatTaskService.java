package kingaidra.chat;

import ghidra.framework.plugintool.ServiceInfo;
import kingaidra.KinGAidraChatPlugin;

//@formatter:off
@ServiceInfo (
	defaultProvider=KinGAidraChatPlugin.class,
	description="service"
)
//@formatter:on
public interface KinGAidraChatTaskService {
    public void add_task(String key, Conversation convo);

    public void commit_task(String key, String msg);

    public Conversation get_task(String key);

    public Conversation pop_task(String key);
}
