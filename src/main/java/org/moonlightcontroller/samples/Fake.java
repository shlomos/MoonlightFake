package org.moonlightcontroller.samples;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.LinkedList;
import java.util.logging.Logger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.moonlightcontroller.samples.actions.Action;
import org.moonlightcontroller.samples.actions.ActionAlert;
import org.moonlightcontroller.samples.actions.ActionDrop;
import org.moonlightcontroller.samples.actions.ActionLog;
import org.moonlightcontroller.samples.actions.ActionOutput;
import org.openboxprotocol.exceptions.InstanceNotAvailableException;
import org.moonlightcontroller.bal.BoxApplication;
import org.moonlightcontroller.blocks.FromDevice;
import org.moonlightcontroller.blocks.FromHost;
import org.moonlightcontroller.blocks.ToHost;
import org.moonlightcontroller.blocks.FromDump;
import org.moonlightcontroller.blocks.HeaderClassifier;
import org.moonlightcontroller.blocks.StringMatcher;
import org.moonlightcontroller.blocks.HeaderClassifier.HeaderClassifierRule;
import org.moonlightcontroller.blocks.ToDevice;
import org.moonlightcontroller.blocks.ToDump;
import org.moonlightcontroller.blocks.Alert;
import org.moonlightcontroller.blocks.Log;
import org.moonlightcontroller.mtd.BlockProtector;
import org.moonlightcontroller.mtd.ApplicationType;
import org.moonlightcontroller.processing.Connector;
import org.moonlightcontroller.processing.IProcessingGraph;
import org.moonlightcontroller.processing.ProcessingGraph;
import org.moonlightcontroller.processing.NetworkStack;
import org.moonlightcontroller.processing.IConnector;
import org.moonlightcontroller.processing.IProcessingBlock;
import org.moonlightcontroller.topology.InstanceLocationSpecifier;
import org.moonlightcontroller.topology.IApplicationTopology;
import org.moonlightcontroller.topology.TopologyManager;
import org.moonlightcontroller.events.IAlertListener;
import org.moonlightcontroller.events.ICastleListener;
import org.moonlightcontroller.events.IHandleClient;
import org.moonlightcontroller.events.IInstanceUpListener;
import org.moonlightcontroller.events.InstanceUpArgs;
import org.moonlightcontroller.events.InstanceAlertArgs;
import org.moonlightcontroller.events.InstanceCastleArgs;
import org.moonlightcontroller.managers.models.IRequestSender;
import org.moonlightcontroller.managers.models.messages.AlertMessage;
import org.moonlightcontroller.managers.models.messages.Error;
import org.moonlightcontroller.managers.models.messages.IMessage;
import org.moonlightcontroller.managers.models.messages.ReadResponse;
import org.openboxprotocol.protocol.HeaderField;
import org.openboxprotocol.protocol.HeaderMatch;
import org.openboxprotocol.protocol.IStatement;
import org.openboxprotocol.protocol.OpenBoxHeaderMatch;
import org.openboxprotocol.protocol.Priority;
import org.openboxprotocol.protocol.Statement;
import org.openboxprotocol.types.TransportPort;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jdk.nashorn.internal.ir.annotations.Immutable;

import com.google.common.collect.ImmutableList;

public class Fake extends BoxApplication {

	private final static Logger LOG = Logger.getLogger(Fake.class.getName());

	public static final String PROPERTIES_PATH = "Fake.properties";

	public static final String PROP_PATTERNS_FILE = "patterns_file";
	public static final String PROP_APPLICATION_TYPE = "app_type";
	public static final String PROP_SEGMENT = "segment";
	public static final String PROP_IN_IFC = "in_ifc";
	public static final String PROP_RULE_FILE = "rule_file";
	public static final String PROP_NETWORK_STACK = "network_stack";
	public static final String PROP_DPI_ALGS = "dpi_algs";

	public static final String DEFAULT_SEGMENT = "220";
	public static final String DEFAULT_IN_IFC = "eth1";
	public static final String DEFAULT_RULE_FILE = "firewall_rules.txt";
	public static final String DEFAULT_NETWORK_STACK = "kernel";
	public static final String DEFAULT_PATTERNS_FILE = "patterns_file";
	public static final String DEFAULT_APPLICATION_TYPE = "0";
	public static final String DEFAULT_DPI_ALGS = "cac,ac,wm,aco";

	private static final Properties DEFAULT_PROPS = new Properties();
	static {
		DEFAULT_PROPS.setProperty(PROP_SEGMENT, DEFAULT_SEGMENT);
		DEFAULT_PROPS.setProperty(PROP_APPLICATION_TYPE, DEFAULT_APPLICATION_TYPE);
		DEFAULT_PROPS.setProperty(PROP_IN_IFC, DEFAULT_IN_IFC);
		DEFAULT_PROPS.setProperty(PROP_PATTERNS_FILE, DEFAULT_PATTERNS_FILE);
		DEFAULT_PROPS.setProperty(PROP_RULE_FILE, DEFAULT_RULE_FILE);
		DEFAULT_PROPS.setProperty(PROP_NETWORK_STACK, DEFAULT_NETWORK_STACK);
		DEFAULT_PROPS.setProperty(PROP_DPI_ALGS, DEFAULT_DPI_ALGS);
	}

	private Properties props;

	public Fake() {
		super("The most Fake app in the world", Priority.HIGH);

		props = new Properties(DEFAULT_PROPS);
		File f = new File(PROPERTIES_PATH);
		try {
			props.load(new FileReader (f));
		} catch (IOException e) {
			LOG.severe("Cannot load properties file from path: " + f.getAbsolutePath());
			LOG.severe("Using default properties.");
		}
		LOG.info(String.format("Fake is running on Segment %s", props.getProperty(PROP_SEGMENT)));
		LOG.info(String.format("[->] Interface for input: %s", props.getProperty(PROP_IN_IFC)));
		LOG.info(String.format("[->] Patterns file path: %s", props.getProperty(PROP_PATTERNS_FILE)));
		LOG.info(String.format("[>|] Rule files path: %s", props.getProperty(PROP_RULE_FILE)));
		LOG.info(String.format("[>|] Network stack: %s", props.getProperty(PROP_NETWORK_STACK)));
		LOG.info(String.format("[>|] dpi algs: %s", props.getProperty(PROP_DPI_ALGS)));

		List<IStatement> statements = createStatements();
		this.setStatements(statements);
		this.setInstanceUpListener(new InstanceUpHandler());
		this.setAlertListener(new FakeAlertListener());
		this.setCastleListener(new FakeCastleListener());
		this.setType(new ApplicationType(Long.parseLong(props.getProperty(PROP_APPLICATION_TYPE))));
	}

	private List<String> readPatterns(String path) {
		List<String> result = new ArrayList<>();
		int ret = 0;
		File f = new File(path);
		BufferedReader reader = null;
		System.out.println("Reading patterns...");
		try {
			char len[] = new char[2];
			int length;
			reader = new BufferedReader(new FileReader(f));
			int index = 0;
			while (true) {
				ret = reader.read(len, 0, 2);
				if (ret <= 0) {
					break;
				} else if (ret < 2) {
					throw new EOFException();
				}
				length = (byte)len[0] << 8 | (byte)len[1];
				char line[] = new char[length];
				if (reader.read(line, 0, length) < 0) {
					throw new EOFException();
				}
				if (index < 1594 || index > 1599) {
					result.add(new String(line));
				}
				index++;
			}
		} catch (IOException e) {
			LOG.severe("Error (" + e.getClass().getName() + ") while reading patterns from file (MESSAGE=" + e.getMessage() + ")");
		} finally {
			if (reader != null) {
				try { reader.close(); } catch (Exception e) { }
			}
		}
		return result;
	}

	private List<String> readPatternsSimple(String path) {
		List<String> result = new ArrayList<>();
		int ret = 0;
		File f = new File(path);
		BufferedReader reader = null;
		System.out.println("Reading patterns simple...");
		try {
			reader = new BufferedReader(new FileReader(f));
			int index = 0;
			while (true) {
				String line;
				line = reader.readLine();
				if (line == null || result.size() > 10000) {
					break;
				} else{
					index++;
					result.add(line);
				}
			}
			LOG.info("Read " + result.size() + " patterns from file " + path);
		} catch (IOException e) {
			LOG.severe("Error (" + e.getClass().getName() + ") while reading patterns from file (MESSAGE=" + e.getMessage() + ")");
		} finally {
			if (reader != null) {
				try { reader.close(); } catch (Exception e) { }
			}
		}
		return result;
	}

	private String readInterfaceHint(String path) {
		byte[] encoded = null;
		try {
			System.out.println("Reading interface hint...");
			encoded = Files.readAllBytes(Paths.get(path));
		} catch (IOException e) {
			LOG.severe("Error (" + e.getClass().getName() + ") while reading patterns from file (MESSAGE=" + e.getMessage() + ")");
			return "";
		}
		String iface = new String(encoded, Charset.defaultCharset());
		System.out.println("Interface hint is " + iface);
		return iface;
	}


	@Override
	public void handleAppStart(IApplicationTopology top, IHandleClient handles) {
		LOG.info("Got Fake App Start Event");
		/*new Thread(()-> {
			for (int i = 0 ; i < 10; i++){
				try {
					handles.readHandle(
							new InstanceLocationSpecifier(220), 
							"monkey",
							"buisness", new FakeRequestSender());
				} catch (InstanceNotAvailableException e1) {
					LOG.warning("Unable to reach OBI");
				}
				try {
					Thread.sleep(10000);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}).start();*/
	}

	private class FakeAlertListener implements IAlertListener {
		
		@Override
		public void Handle(InstanceAlertArgs args) {
			org.moonlightcontroller.managers.models.messages.Alert alert = args.getAlert();
			for (AlertMessage msg : alert.getMessages()) {
				LOG.info("got an alert from block:" + args.getBlock().getId() + "::" + msg.getMessage());	
			}
			
		}
	}

	private class FakeCastleListener implements ICastleListener {
		
		@Override
		public void Handle(InstanceCastleArgs args) {
			org.moonlightcontroller.managers.models.messages.Castle castle = args.getCastle();
			LOG.info("got a castle request from block:" + args.getBlock().getId());	
		}
	}
	
	private class FakeRequestSender implements IRequestSender {

		@Override
		public void onSuccess(IMessage message) {
			if (message instanceof ReadResponse){
				ReadResponse rr = (ReadResponse)message;
				LOG.info("got a read response:" + rr.getBlockId() + "::" + rr.getReadHandle() + "::" + rr.getResult());
			}
		}

		@Override
		public void onFailure(Error err) {
			LOG.info("got an error:" + err.getError_type() + "::" + err.getExtended_message());
		}
	}

	private String find_interface(String name) {
		String iface = name;

		try {
                        Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
                        System.out.println(nets);
                        for (NetworkInterface netint : Collections.list(nets)) {
                                System.out.println("Checking: " + netint.getName() + " vs " + name);
                                System.out.println(netint.getName() + " == " + name + " is " + netint.getName().contains(name.trim()));
                                if (netint.getName().contains(name.trim())) {
                                        iface = netint.getName();
                                        break;
                                }
                        }
                } catch (SocketException exp) {
                        System.out.print("socket exception while enumerating interfaces");
                }
		return iface;
	}

	private List<IStatement> createStatements(){
		String name = props.getProperty(PROP_IN_IFC);
		NetworkStack net_stack = NetworkStack.valueOf(props.getProperty(PROP_NETWORK_STACK).toUpperCase());
		String iface = name;

		if (net_stack != NetworkStack.DPDK) {
			iface = find_interface(name);
		}

		List<IConnector> connectors = new ArrayList<>();
		List<IProcessingBlock> blocks = new ArrayList<>();
		FromDevice from;

		if (net_stack != NetworkStack.KERNEL) {
			from = new FromDevice("FromDevice_FakeApp", iface, false, true, net_stack);
		} else {
			from = new FromDevice("FromDevice_FakeApp", iface, true, true, net_stack);
		}
		Map<String, IProcessingBlock> toDeviceBlocks = new HashMap<>();
		Map<String, Alert> alertBlocks = new HashMap<>();
		//FromHost fh = new FromHost("FromHost_FakeApp", "virt");
		//ToHost th = new ToHost("ToHost_FakeApp", "virt");
		ToDump discard = new ToDump("ToDump3_FakeApp", "/home/user/hello_malicious.pcap");
		Alert alert = new Alert("Alert_FakeApp", "DPI malicious packet alert", 1, true, 1000);
		//ToDevice to = new ToDevice("ToDevice_FakeApp_" + props.getProperty(PROP_IN_IFC), props.getProperty(PROP_IN_IFC), false);

		blocks.add(from);
		//blocks.add(alert);
		//blocks.add(fh);
		//blocks.add(to);
		//blocks.add(th);
		blocks.add(discard);
		// ===================== Snort ==========================
		List<String> dpiPatterns = readPatternsSimple(props.getProperty(PROP_PATTERNS_FILE));
		List<StringMatcher> dpis = new LinkedList<>();
		alertBlocks.put(alert.getMessage(), alert);
		Set<String> dpi_algs = new HashSet<String>(Arrays.asList(props.getProperty(PROP_DPI_ALGS).split(",")));
		//toDeviceBlocks.put(props.getProperty(PROP_IN_IFC), to);
		if(dpi_algs.contains("wm"))
			dpis.add(new StringMatcher("StringMatcher_WM_FakeApp", dpiPatterns, "wumanber", true)); // choose from: wumanber, ahocorasick, compressedahocorasick
		if(dpi_algs.contains("ac"))
			dpis.add(new StringMatcher("StringMatcher_AC_FakeApp", dpiPatterns, "ahocorasick", true));
		if(dpi_algs.contains("aco"))
			dpis.add(new StringMatcher("StringMatcher_ACO_FakeApp", dpiPatterns, "ahocorasick_other", true));
		if(dpi_algs.contains("cac"))
			dpis.add(new StringMatcher("StringMatcher_CAC_FakeApp", dpiPatterns, "compressedahocorasick", true));
		// ===================== Firewall =======================
		List<HeaderClassifierRule> headerRules = new ArrayList<>();
		List<Rule> rules;

		try {
			RuleParser rp = new RuleParser(props.getProperty(PROP_RULE_FILE));
			System.out.println("After rp!");
			rules = rp.read();
		} catch (Exception e) {
			LOG.severe("Failed to parse rule file: " + e.getMessage() + "\n" + e.getStackTrace());
			return ImmutableList.of();
		}

		HeaderClassifier classify = new HeaderClassifier("HeaderClassifier_FakeApp", headerRules, Priority.HIGH, false);
		blocks.add(classify);

		connectors.add(new Connector.Builder()
				.setSourceBlock(from)
				.setSourceOutputPort(0)
				.setDestBlock(classify).build()
		);
		// connectors.add(new Connector.Builder()
		// 		.setSourceBlock(alert)
		// 		.setSourceOutputPort(0)
		// 		.setDestBlock(discard).build()
		// );

		// ========================= Graph ========================

		IStatement.Builder stb = new Statement.Builder();
		stb.setLocation(TopologyManager.getInstance().resolve(220));

		for (StringMatcher dpi: dpis) {
			toDeviceBlocks.clear();
			alertBlocks.clear();
			headerRules.clear();
			List<IConnector> snort_connectors = new ArrayList<>();
			List<IProcessingBlock> snort_blocks = new ArrayList<>();

			BlockProtector prot = BlockProtector.getInstance();
			IProcessingGraph prot_hdr_clas;
			List<IProcessingBlock> prot_blocks;
			IProcessingBlock prot_out;

			// Add header FW
			int i = 0;
			for (Rule r : rules) {
				headerRules.add(new HeaderClassifierRule.Builder()
					.setHeaderMatch(r.getHeaderMatch())
					.setPriority(r.getPriority())
					.setOrder(i)
					.build());

				IProcessingBlock last = classify;
				int lastOutPort = i;
				int j = 0;
				boolean stop = false;
				boolean exists;
				for (Action action : r.getActions()) {
					IProcessingBlock destBlock;
					IProcessingBlock blockToAdd;
					exists = false;
					String suffix = String.format("_Firewall_Rule_%d_UID_%d", i, j);
					String msg;
					if (action instanceof ActionAlert) {
						msg = ((ActionAlert)action).getMessage();
						if (alertBlocks.containsKey(((ActionAlert)action).getMessage())) {
							destBlock = alertBlocks.get(msg);
							blockToAdd = destBlock;
							exists = true;
						} else {
							Alert newBlock = new Alert("Alert_FakeApp" + suffix, msg);
							alertBlocks.put(msg, newBlock);
							destBlock = newBlock;
							blockToAdd = destBlock;
						}
					} else if (action instanceof ActionOutput) {
						String out_iface = ((ActionOutput)action).getInterface();
						if (toDeviceBlocks.containsKey(out_iface)) {
							destBlock = toDeviceBlocks.get(out_iface);
							blockToAdd = destBlock;
							exists = true;
						} else {
							ToDevice newBlock = new ToDevice("ToDevice_FakeApp_" + out_iface, out_iface, net_stack);
							double thresh = 1.5;
							if (dpi.getMatcherType().equals("wumanber")) {
								thresh = 4.0;
							}
							prot_hdr_clas = prot.getProtectedSubGraph(dpi, 2, 10000, thresh);
							prot_blocks = prot_hdr_clas.getBlocks();
							prot_out = prot_blocks.get(prot_blocks.size() - 1);
							snort_connectors.add(new Connector.Builder()
									.setSourceBlock(prot_out)
									.setSourceOutputPort(0)
									.setDestBlock(newBlock).build()
							);
							snort_connectors.add(new Connector.Builder()
									.setSourceBlock(prot_out)
									.setSourceOutputPort(1)
									.setDestBlock(discard).build()
							);
							snort_blocks.addAll(prot_blocks);
							snort_connectors.addAll(prot_hdr_clas.getConnectors());
							destBlock = prot_hdr_clas.getRoot();
							blockToAdd = newBlock;
							toDeviceBlocks.put(out_iface, destBlock);
						}
					} else if (action instanceof ActionDrop) {
						destBlock = discard;
						blockToAdd = destBlock;
						exists = true;
						stop = true;
					} else if (action instanceof ActionLog) {
						msg = ((ActionLog)action).getMessage();
						destBlock = new Log("Log" + suffix, msg);
						blockToAdd = destBlock;
					} else {
						LOG.severe("Unknown action: " + action.getType());
						continue;
					}
					if (!exists)
						snort_blocks.add(blockToAdd);

					snort_connectors.add(new Connector.Builder().setSourceBlock(last).setSourceOutputPort(lastOutPort).setDestBlock(destBlock).build());
					last = destBlock;
					lastOutPort = 0;
					j++;
					if (stop)
						break;
				}
				i++;
			}
			// end
			IProcessingGraph graph = new ProcessingGraph.Builder()
				.setBlocks(Stream.concat(blocks.stream(), snort_blocks.stream())
					.collect(Collectors.toList()))
				.setConnectors(Stream.concat(connectors.stream(), snort_connectors.stream())
					.collect(Collectors.toList()))
				.setRoot(from)
				.build();

			System.out.println(graph.getBlocks());
			stb.setProcessingGraph(graph);
		}
		
		return Collections.singletonList(stb.build());
	}

	private class InstanceUpHandler implements IInstanceUpListener {

		@Override
		public void Handle(InstanceUpArgs args) {
			LOG.info("Instance up for Fake: " + args.getInstance().toString());	
		}
	}
}
