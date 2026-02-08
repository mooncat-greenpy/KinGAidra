package kingaidra.ai.convo;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;


public class Message implements Serializable {

	private static final long serialVersionUID = 1L;

	private String role;
	private String content;
	private String tool_call_id;
	private List<Map<String, Object>> tool_calls;

	public Message(String role, String content) {
		this.role = role;
		this.content = content;
	}

	public Message(String role, String content, String tool_call_id, List<Map<String, Object>> tool_calls) {
		this.role = role;
		this.content = content;
		this.tool_call_id = tool_call_id;
		this.tool_calls = tool_calls;
	}

	@JsonProperty("role")
	public String get_role() {
		return role;
	}

	@JsonProperty("content")
	public String get_content() {
		return content;
	}

	@JsonProperty("tool_call_id")
	public String get_tool_call_id() {
		return tool_call_id;
	}

	@JsonProperty("tool_calls")
	public List<Map<String, Object>> get_tool_calls() {
		return tool_calls;
	}

	@SuppressWarnings("unchecked")
	public static Message from_map(Map<String, Object> map) {
		if (map == null) {
			return null;
		}
		if (map.containsKey("role")) {
			String role = to_string(map.get("role"));
			String content = to_string(map.get("content"));
			String tool_call_id = to_string(map.get("tool_call_id"));
			List<Map<String, Object>> tool_calls = extract_tool_calls(map.get("tool_calls"));
			return new Message(role, content, tool_call_id, tool_calls);
		}
		if (map.containsKey("type") && map.get("data") instanceof Map) {
			String type = to_string(map.get("type"));
			Map<String, Object> data = (Map<String, Object>) map.get("data");
			String role = map_type_to_role(type, data);
			String content = to_string(data.get("content"));
			String tool_call_id = to_string(data.get("tool_call_id"));
			List<Map<String, Object>> tool_calls = extract_tool_calls(data.get("tool_calls"));
			if (tool_calls == null && data.get("additional_kwargs") instanceof Map) {
				Map<String, Object> additional = (Map<String, Object>) data.get("additional_kwargs");
				tool_calls = extract_tool_calls(additional.get("tool_calls"));
			}
			return new Message(role, content, tool_call_id, tool_calls);
		}
		return null;
	}

	private static String to_string(Object value) {
		if (value == null) {
			return null;
		}
		return value.toString();
	}

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> extract_tool_calls(Object tool_calls_value) {
		if (!(tool_calls_value instanceof List)) {
			return null;
		}
		List<?> raw_list = (List<?>) tool_calls_value;
		List<Map<String, Object>> tool_calls = new ArrayList<>(raw_list.size());
		for (Object item : raw_list) {
			if (item instanceof Map) {
				tool_calls.add((Map<String, Object>) item);
			}
		}
		return tool_calls.isEmpty() ? null : tool_calls;
	}

	private static String map_type_to_role(String type, Map<String, Object> data) {
		if (type == null) {
			return to_string(data.get("role"));
		}
		if (type.equals("human")) {
			return Conversation.USER_ROLE;
		}
		if (type.equals("ai")) {
			return Conversation.ASSISTANT_ROLE;
		}
		if (type.equals("system")) {
			return Conversation.SYSTEM_ROLE;
		}
		if (type.equals("tool")) {
			return Conversation.TOOL_ROLE;
		}
		String role = to_string(data.get("role"));
		return role == null ? type : role;
	}
}
