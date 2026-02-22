package kingaidra.chat.workflow;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ChatWorkflow {
    private final String popup_name;
    private final List<String> step_prompts;
    private final String system_prompt;

    public ChatWorkflow(String popup_name, List<String> step_prompts) {
        this(popup_name, step_prompts, null);
    }

    public ChatWorkflow(String popup_name, List<String> step_prompts, String system_prompt) {
        this.popup_name = popup_name;
        this.step_prompts = new ArrayList<>(step_prompts);
        this.system_prompt = system_prompt;
    }

    public String get_popup_name() {
        return popup_name;
    }

    public List<String> get_step_prompts() {
        return Collections.unmodifiableList(step_prompts);
    }

    public String get_system_prompt() {
        return system_prompt;
    }
}
