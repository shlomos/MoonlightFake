package org.moonlightcontroller.samples;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.moonlightcontroller.samples.actions.Action;
import org.moonlightcontroller.samples.actions.ActionAlert;
import org.moonlightcontroller.samples.actions.ActionDrop;
import org.moonlightcontroller.samples.actions.ActionLog;
import org.moonlightcontroller.samples.actions.ActionOutput;
import org.openboxprotocol.exceptions.JSONParseException;
import org.openboxprotocol.protocol.HeaderField;
import org.openboxprotocol.protocol.HeaderMatch;
import org.openboxprotocol.protocol.OpenBoxHeaderMatch;
import org.openboxprotocol.protocol.Priority;
import org.openboxprotocol.types.EthType;
import org.openboxprotocol.types.IPv4Address;
import org.openboxprotocol.types.IPv6Address;
import org.openboxprotocol.types.IpDscp;
import org.openboxprotocol.types.IpEcn;
import org.openboxprotocol.types.IpProto;
import org.openboxprotocol.types.MacAddress;
import org.openboxprotocol.types.TransportPort;
import org.openboxprotocol.types.ValueType;
import org.openboxprotocol.types.VlanPcp;
import org.openboxprotocol.types.VlanVid;

import com.google.common.collect.ImmutableList;

public class RuleParser {
	
	private static final Map<String, HeaderField<?>> HEADER_MATCH_TRANSLATION;
	
	static {
		HEADER_MATCH_TRANSLATION = new HashMap<String, HeaderField<?>>();
		HEADER_MATCH_TRANSLATION.put("eth_type", HeaderField.ETH_TYPE);
		HEADER_MATCH_TRANSLATION.put("eth_src", HeaderField.ETH_SRC);
		HEADER_MATCH_TRANSLATION.put("eth_dst", HeaderField.ETH_DST);
		HEADER_MATCH_TRANSLATION.put("vlan_vid", HeaderField.VLAN_VID);
		HEADER_MATCH_TRANSLATION.put("vlan_pcp", HeaderField.VLAN_PCP);
		HEADER_MATCH_TRANSLATION.put("ip_proto", HeaderField.IP_PROTO);
		HEADER_MATCH_TRANSLATION.put("ip_dscp", HeaderField.IP_DSCP);
		HEADER_MATCH_TRANSLATION.put("ip_ecn", HeaderField.IP_ECN);
		HEADER_MATCH_TRANSLATION.put("ipv4_src", HeaderField.IPV4_SRC);
		HEADER_MATCH_TRANSLATION.put("ipv4_dst", HeaderField.IPV4_DST);
		HEADER_MATCH_TRANSLATION.put("ipv6_src", HeaderField.IPV6_SRC);
		HEADER_MATCH_TRANSLATION.put("ipv6_dst", HeaderField.IPV6_DST);
		HEADER_MATCH_TRANSLATION.put("tcp_src", HeaderField.TCP_SRC);
		HEADER_MATCH_TRANSLATION.put("tcp_dst", HeaderField.TCP_DST);
		HEADER_MATCH_TRANSLATION.put("udp_src", HeaderField.UDP_SRC);
		HEADER_MATCH_TRANSLATION.put("udp_dst", HeaderField.UDP_DST);
	}

	private String path;
	
	public RuleParser(String path) {
		this.path = path;
	}
	
	public List<Rule> read() throws IOException, org.json.simple.parser.ParseException, JSONParseException {
		BufferedReader reader = null;
		
		try {
			reader = new BufferedReader(new FileReader(path));
			return readRulesFromFile(reader);
		} catch (JSONParseException e) {
			e.printStackTrace();
			throw e;
		} catch (ParseException e) {
			e.printStackTrace();
			throw e;
		} catch (IOException e) {
			e.printStackTrace();
			throw e;
		} finally {
			if (reader != null) {
				reader.close();
			}
		}
	}
	
	@SuppressWarnings("unchecked")
	private List<Rule> readRulesFromFile(Reader reader) throws IOException, org.json.simple.parser.ParseException, JSONParseException {
        JSONParser parser = new JSONParser();
        JSONArray rules = (JSONArray)((Map<String, ?>)parser.parse(reader)).get("rules");
		Iterator<?> iter = rules.listIterator();
		List<Rule> result = new ArrayList<>();
		while (iter.hasNext()) {
            Map<String,?> jrule = (Map<String,?>)iter.next();
			Map<String,?> jHeaderMatch = (Map<String,?>)jrule.get("match");
			HeaderMatch headerMatch = jsonToHeaderMatch(jHeaderMatch);
			//Map<String,?> jPayloadMatch = (Map<String,?>)jrule.get("payload_match");
			//PayloadMatch payloadMatch = jsonToPayloadMatch(jPayloadMatch);
			List<?> jActions = (List<?>)jrule.get("actions");
			List<Action> actions = jsonToActions(jActions);
			
			Priority priority = Priority.MEDIUM;
			
			if (jrule.containsKey("priority")) {
				priority = Priority.valueOf((String)jrule.get("priority"));
			}
			
			result.add(new Rule(priority, headerMatch, actions));
		}
		
		return ImmutableList.copyOf(result);
	}
	
	@SuppressWarnings("unchecked")
	private List<Action> jsonToActions(List<?> json) throws JSONParseException {
		List<Action> result = new ArrayList<Action>();
		for (Object obj : json) {
			if (obj instanceof String) {
				// "alert", "log", "drop"
				if (((String)obj).equalsIgnoreCase("alert")) {
					result.add(new ActionAlert.Builder().build());
				} else if (((String)obj).equalsIgnoreCase("log")) {
					result.add(new ActionLog.Builder().build());
				} else if (((String)obj).equalsIgnoreCase("drop")) {
					result.add(new ActionDrop.Builder().build());
				}
			} else if (obj instanceof Map) {
				Map<String, ?> map = (Map<String,?>)obj;
				String type = (String)map.get("type");
				if (type.equalsIgnoreCase("output")) {
					String iface = (String)map.get("interface");
					result.add(new ActionOutput.Builder(iface).build());
				} else if (type.equalsIgnoreCase("alert")) {
					String msg = (String)map.get("message");
					result.add(new ActionAlert.Builder(msg).build());
				} else if (type.equalsIgnoreCase("log")) {
					result.add(new ActionLog.Builder().build());
				} else if (type.equalsIgnoreCase("drop")) {
					result.add(new ActionDrop.Builder().build());
				}
			}
		}
		return ImmutableList.copyOf(result);
	}
	
	/*
	@SuppressWarnings("unchecked")
	private PayloadMatch jsonToPayloadMatch(Map<String,?> json) throws JSONParseException {
		PayloadMatch.Builder builder = new OpenBoxPayloadMatch.Builder();
		List<Object> pats = (List<Object>)json.get("patterns");
		for (Object pat : pats) {
			PayloadPattern pattern = jsonToPayloadPattern((Map<String,?>)pat);
			builder.addPattern(pattern);
		}
		return builder.build();
	}
	
	private PayloadPattern jsonToPayloadPattern(Map<String,?> json) throws JSONParseException {
		String pattern;
		boolean regex;
		int from = -1, to = -1;
		
		if (json.containsKey("string")) {
			pattern = (String)json.get("string");
			regex = false;
		} else if (json.containsKey("regex")) {
			pattern = (String)json.get("regex");
			regex = true;
		} else {
			throw new JSONParseException("Pattern must contain either a string or a regular expression");
		}
		
		if (json.containsKey("from")) {
			Object v = json.get("from");
			if (v instanceof Integer) {
				from = (Integer)v;
			} else {
				throw new JSONParseException("Invalid value for field 'from' of pattern '" + pattern + "': " + v);
			}
		}

		if (json.containsKey("to")) {
			Object v = json.get("to");
			if (v instanceof Integer) {
				to = (Integer)v;
			} else {
				throw new JSONParseException("Invalid value for field 'to' of pattern '" + pattern + "': " + v);
			}
		}

		if ((from != -1 && from < 0) ||(to != -1 && to < 0) || (from != -1 && to != -1 && to < from)) {
			throw new JSONParseException("Invalid search range for pattern '" + pattern + "'");
		}
		
		if (!regex) {
			return new ExactPattern(pattern, from, to);
		} else {
			return new RegexPattern(pattern, from, to);
		}
	}
	*/
	
	@SuppressWarnings("unchecked")
	private static <F extends ValueType<F>> void setField(HeaderMatch.Builder builder, Class<F> c, HeaderField<F> field, Object value, Object mask) throws JSONParseException {
		F v, m = null;
		try {
			Method method = c.getMethod("fromJson", Object.class);
			v = (F)method.invoke(null, value);
			if (mask != null)
				m = (F)method.invoke(null, mask);
			if (m == null)
				builder.setExact(field, v);
			else
				builder.setMasked(field, v, m);
		} catch (InvocationTargetException e) {
			Throwable cause = e.getCause();
			if (cause instanceof JSONParseException)
				throw (JSONParseException)cause;
			else
				throw new JSONParseException("Cannot parse JSON value: " + value + " (" + cause.getMessage() + ")");
		} catch (Exception e) {
			throw new JSONParseException("Cannot parse JSON value: " + value + " (" + e.getMessage() + ")");
		}
	}
	
	private HeaderMatch jsonToHeaderMatch(Map<String,?> json) throws JSONParseException {
		HeaderMatch.Builder builder = new OpenBoxHeaderMatch.Builder();
		for (Entry<String, ?> entry : json.entrySet()) {
			if (entry.getKey().endsWith("_mask"))
				continue;
			
			HeaderField<?> field = HEADER_MATCH_TRANSLATION.get(entry.getKey());
			if (field == null) {
				throw new JSONParseException("Unknown header match field: " + entry.getKey());
			}
			
			Object value = entry.getValue();
			Object mask = null;
			if (json.containsKey(entry.getKey() + "_mask")) {
				mask = json.get(entry.getKey() + "_mask");
			}
			
			switch (field.id) {
			case ETH_TYPE:
				setField(builder, EthType.class, HeaderField.ETH_TYPE, value, mask);
				break;
			case ETH_SRC:
				setField(builder, MacAddress.class, HeaderField.ETH_SRC, value, mask);
				break;
			case ETH_DST:
				setField(builder, MacAddress.class, HeaderField.ETH_DST, value, mask);
				break;
			case VLAN_VID:
				setField(builder, VlanVid.class, HeaderField.VLAN_VID, value, mask);
				break;
			case VLAN_PCP:
				setField(builder, VlanPcp.class, HeaderField.VLAN_PCP, value, mask);
				break;
			case IP_PROTO:
				setField(builder, IpProto.class, HeaderField.IP_PROTO, value, mask);
				break;
			case IP_DSCP:
				setField(builder, IpDscp.class, HeaderField.IP_DSCP, value, mask);
				break;
			case IP_ECN:
				setField(builder, IpEcn.class, HeaderField.IP_ECN, value, mask);
				break;
			case IPV4_SRC:
				setField(builder, IPv4Address.class, HeaderField.IPV4_SRC, value, mask);
				break;
			case IPV4_DST:
				setField(builder, IPv4Address.class, HeaderField.IPV4_DST, value, mask);
				break;
			case IPV6_SRC:
				setField(builder, IPv6Address.class, HeaderField.IPV6_SRC, value, mask);
				break;
			case IPV6_DST:
				setField(builder, IPv6Address.class, HeaderField.IPV6_DST, value, mask);
				break;
			case TCP_SRC:
				setField(builder, TransportPort.class, HeaderField.TCP_SRC, value, mask);
				break;
			case TCP_DST:
				setField(builder, TransportPort.class, HeaderField.TCP_DST, value, mask);
				break;
			case UDP_SRC:
				setField(builder, TransportPort.class, HeaderField.UDP_SRC, value, mask);
				break;
			case UDP_DST:
				setField(builder, TransportPort.class, HeaderField.UDP_DST, value, mask);
				break;
			default:
				// Ignore for now...
				break;
			}
		}
		return builder.build();
	}
	
}
