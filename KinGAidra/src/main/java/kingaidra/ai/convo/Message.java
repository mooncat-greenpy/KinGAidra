package kingaidra.ai.convo;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonProperty;


public class Message implements Serializable {

	private String role;
	private String content;

	public Message(String role, String content) {
		this.role = role;
		this.content = content;
	}

	@JsonProperty("role")
	public String get_role() {
		return role;
	}

	@JsonProperty("content")
	public String get_content() {
		return content;
	}
}
