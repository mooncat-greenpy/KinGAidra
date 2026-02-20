//@author mooncat-greenpy
//@category KinGAidra
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.task.TaskMonitor;
import kingaidra.ai.Ai;
import kingaidra.ai.convo.Conversation;
import kingaidra.ai.convo.ConversationContainer;
import kingaidra.ai.convo.ConversationContainerGhidraProgram;
import kingaidra.ai.convo.ConversationType;
import kingaidra.ai.model.Model;
import kingaidra.ai.model.ModelByScript;
import kingaidra.ai.model.ModelConfSingle;
import kingaidra.ai.task.KinGAidraChatTaskService;
import kingaidra.ai.task.TaskType;
import kingaidra.ghidra.ChatModelPreferences;
import kingaidra.ghidra.GhidraUtil;
import kingaidra.ghidra.GhidraUtilImpl;
import kingaidra.ghidra.PromptConf;

public class kingaidra_headless_chat extends GhidraScript {

    private static final String DEFAULT_OUTPUT_SUFFIX = "_kingaidra_headless_chat.md";

    private static final class Opts {
        private String question = null;
        private String model_script = null;
        private String output = null;
        private boolean help = false;
    }

    private void print_usage() {
        println("Usage:");
        println("  analyzeHeadless ... -postScript kingaidra_headless_chat.java \\");
        println("    --question \"<prompt>\" [--output <path>] \\");
        println("    [--model-script <script.py>]");
    }

    private String get_arg_value(String[] args, int idx, String key) {
        if (idx + 1 >= args.length) {
            throw new IllegalArgumentException("Missing value for argument: " + key);
        }
        return args[idx + 1];
    }

    private Opts parse_args(String[] args) {
        Opts opts = new Opts();

        for (int i = 0; i < args.length; i++) {
            String token = args[i];

            if ("-h".equals(token) || "--help".equals(token)) {
                opts.help = true;
                continue;
            }
            if ("-q".equals(token) || "--question".equals(token)) {
                opts.question = get_arg_value(args, i, token);
                i += 1;
                continue;
            }
            if ("-o".equals(token) || "--output".equals(token)) {
                opts.output = get_arg_value(args, i, token);
                i += 1;
                continue;
            }
            if ("--model-script".equals(token)) {
                opts.model_script = get_arg_value(args, i, token);
                i += 1;
                continue;
            }

            if (opts.question == null) {
                opts.question = token;
            } else {
                opts.question += "\n" + token;
            }
        }

        return opts;
    }

    private String resolve_output_path(String output) {
        if (output == null || output.isEmpty()) {
            output = currentProgram.getName() + DEFAULT_OUTPUT_SUFFIX;
        }
        return new File(output).getAbsolutePath();
    }

    private String get_last_assistant(Conversation convo) {
        if (convo == null) {
            return "";
        }
        for (int i = convo.get_msgs_len() - 1; i >= 0; i--) {
            String role = convo.get_role(i);
            if (Conversation.ASSISTANT_ROLE.equals(role)) {
                String msg = convo.get_msg(i);
                return msg == null ? "" : msg;
            }
        }
        return "";
    }

    private void write_markdown(String output_path, String markdown) throws Exception {
        File out_file = new File(output_path);
        File parent = out_file.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        BufferedWriter writer = new BufferedWriter(new FileWriter(out_file, false));
        try {
            writer.write(markdown == null ? "" : markdown);
        } finally {
            writer.close();
        }
    }

    private Model get_active_model(ModelConfSingle model_conf) {
        for (String model_name : model_conf.get_models()) {
            Model model = model_conf.get_model(model_name);
            if (model != null && model.get_active()) {
                return model;
            }
        }
        return null;
    }

    private Model resolve_model(Opts opts) {
        if (opts.model_script != null && !opts.model_script.isEmpty()) {
            Model model = new ModelByScript("HeadlessChat", opts.model_script, true);
            return model;
        }

        ModelConfSingle model_conf = new ModelConfSingle("Chat and others", new ChatModelPreferences("chat"));
        Model active = get_active_model(model_conf);
        if (active != null) {
            return active;
        }

        throw new IllegalStateException("No active model. Configure chat models first.");
    }

    @Override
    public void run() throws Exception {
        Opts opts;
        try {
            opts = parse_args(getScriptArgs());
        } catch (IllegalArgumentException e) {
            printerr(e.getMessage());
            print_usage();
            throw e;
        }

        if (opts.help) {
            print_usage();
            return;
        }
        if (opts.question == null || opts.question.trim().isEmpty()) {
            throw new IllegalArgumentException("Question is required. Use --question \"...\"");
        }

        String output_path = resolve_output_path(opts.output);

        PluginTool tool = state.getTool();
        KinGAidraChatTaskService srv = null;
        GhidraUtil ghidra = new GhidraUtilImpl(currentProgram, TaskMonitor.DUMMY);
        ConversationContainer container = new ConversationContainerGhidraProgram(currentProgram, ghidra);
        PromptConf conf = new PromptConf();
        Ai ai = new Ai(tool, currentProgram, ghidra, container, srv, conf);
        ai.set_ghidra_state(state);

        Model model = resolve_model(opts);
        Conversation convo = new Conversation(ConversationType.USER_CHAT, model);
        convo.set_model(model);

        Conversation result = ai.guess(TaskType.CHAT, convo, opts.question, null);
        if (result == null) {
            throw new RuntimeException("LLM call failed. Check model script and API settings.");
        }

        String assistant = get_last_assistant(result);
        write_markdown(output_path, assistant);
        println("Output saved: " + output_path);
    }
}
