package org.moonlightcontroller.samples;

import java.util.List;

import org.moonlightcontroller.samples.actions.Action;
import org.openboxprotocol.protocol.HeaderMatch;
import org.openboxprotocol.protocol.PayloadMatch;
import org.openboxprotocol.protocol.Priority;

public class Rule {

	private Priority priority;
	private HeaderMatch headerMatch;
	private PayloadMatch payloadMatch;
	private List<Action> actions;
	
	public Rule(Priority priority, HeaderMatch headerMatch, List<Action> actions) {
		this(priority, headerMatch, null, actions);
	}
	
	public Rule(Priority priority, HeaderMatch headerMatch,
			PayloadMatch payloadMatch, List<Action> actions) {
		this.priority = priority;
		this.headerMatch = headerMatch;
		this.payloadMatch = payloadMatch;
		this.actions = actions;
	}
	
	public Priority getPriority() {
		return priority;
	}
	
	public HeaderMatch getHeaderMatch() {
		return headerMatch;
	}
	
	public PayloadMatch getPayloadMatch() {
		return payloadMatch;
	}

	public List<Action> getActions() {
		return actions;
	}
	
}
