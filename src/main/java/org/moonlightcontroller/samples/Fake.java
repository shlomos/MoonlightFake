package org.moonlightcontroller.samples;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.LinkedList;
import java.util.logging.Logger;

import org.openboxprotocol.exceptions.InstanceNotAvailableException;
import org.moonlightcontroller.bal.BoxApplication;
import org.moonlightcontroller.blocks.FromDevice;
import org.moonlightcontroller.blocks.FromDump;
import org.moonlightcontroller.blocks.HeaderClassifier;
import org.moonlightcontroller.blocks.StringMatcher;
import org.moonlightcontroller.blocks.HeaderClassifier.HeaderClassifierRule;
import org.moonlightcontroller.blocks.ToDevice;
import org.moonlightcontroller.blocks.ToDump;
import org.moonlightcontroller.blocks.Alert;
import org.moonlightcontroller.mtd.BlockProtector;
import org.moonlightcontroller.mtd.ApplicationType;
import org.moonlightcontroller.processing.Connector;
import org.moonlightcontroller.processing.IProcessingGraph;
import org.moonlightcontroller.processing.ProcessingGraph;
import org.moonlightcontroller.processing.IConnector;
import org.moonlightcontroller.processing.IProcessingBlock;
import org.moonlightcontroller.topology.InstanceLocationSpecifier;
import org.moonlightcontroller.topology.IApplicationTopology;
import org.moonlightcontroller.topology.TopologyManager;
import org.moonlightcontroller.events.IAlertListener;
import org.moonlightcontroller.events.IHandleClient;
import org.moonlightcontroller.events.IInstanceUpListener;
import org.moonlightcontroller.events.InstanceUpArgs;
import org.moonlightcontroller.events.InstanceAlertArgs;
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

import com.google.common.collect.ImmutableList;

public class Fake extends BoxApplication {

	private final static Logger LOG = Logger.getLogger(Fake.class.getName());

	public static final String PROP_PATTERNS_FILE = "patterns_file";
	public static final long PROP_APPLICATION_TYPE = 0;

	public Fake() {
		super("The most Fake app in the world", Priority.HIGH);
		List<IStatement> statements = createStatements();
		System.out.println("KOKO" + statements.get(0).getLocation().getId());
		this.setStatements(statements);
		this.setInstanceUpListener(new InstanceUpHandler());
		this.setAlertListener(new FakeAlertListener());
		this.setType(new ApplicationType(PROP_APPLICATION_TYPE));
	}

	private List<String> readPatterns(String path) {
		List<String> result = new ArrayList<>();
		
		File f = new File(path);
		
		BufferedReader reader = null;
		System.out.println("Reading patterns");
		try {
			char len[] = new char[2];
			int length;
			reader = new BufferedReader(new FileReader(f));
			int index = 0;
			while (true) {
				if (reader.read(len, 0, 2) < 2) {
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
			LOG.severe("Error (" + e.getClass().getName() + ") while reading patterns from file: " + e.getMessage());
		} finally {
			if (reader != null) {
				try { reader.close(); } catch (Exception e) { }
			}
		}
		return result;
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

	private List<IStatement> createStatements() {
		HeaderMatch h1 = new OpenBoxHeaderMatch.Builder().setExact(HeaderField.TCP_DST, new TransportPort(22)).build();
		HeaderMatch h2 = new OpenBoxHeaderMatch.Builder().build();
		ArrayList<HeaderClassifierRule> rules = new ArrayList<HeaderClassifierRule>(Arrays.asList(
				new HeaderClassifierRule.Builder().setHeaderMatch(h1).setPriority(Priority.HIGH).setOrder(0).build(),
				new HeaderClassifierRule.Builder().setHeaderMatch(h2).setPriority(Priority.HIGH).setOrder(1).build()));
		//FromDevice from = new FromDevice("FromDevice_FakeApp", "eth0", true, true);
		FromDump from = new FromDump("FromDump_FakeApp", "/home/mininet/openbox/MoonlightFake/dummy_dump.pcap");
		ToDump to1 = new ToDump("ToDump1_FakeApp", "/home/mininet/hello_ssh.pcap");
		ToDump to2 = new ToDump("ToDump2_FakeApp", "/home/mininet/hello_rest.pcap");
		ToDump discard = new ToDump("ToDump3_FakeApp", "/home/mininet/hello_malicious.pcap");
		List<String> dpiPatterns = readPatterns(PROP_PATTERNS_FILE);
		HeaderClassifier classify = new HeaderClassifier("Classify_FakeApp", rules, Priority.HIGH, false);
		List<StringMatcher> dpis = new LinkedList<>();
		dpis.add(new StringMatcher("StringMatcher_WM_FakeApp", dpiPatterns, "wumanber")); // chhose from: wumanber, ahocorasick
		dpis.add(new StringMatcher("StringMatcher_AC_FakeApp", dpiPatterns, "ahocorasick"));
		Alert alert = new Alert("Alert_Fake", "Alert from Fake", 1, true, 1000);
		//Discard discard = new Discard("Discard_Snort");

		IStatement.Builder stb = new Statement.Builder();
		stb.setLocation(TopologyManager.getInstance().resolve(220));

		for (StringMatcher dpi: dpis) {
			List<IConnector> connectors = new ArrayList<>();
			List<IProcessingBlock> blocks = new ArrayList<>();

			BlockProtector prot = BlockProtector.getInstance();
			IProcessingGraph prot_hdr_clas = prot.getProtectedSubGraph(dpi, 2, 10, 2);
			List<IProcessingBlock> prot_blocks = prot_hdr_clas.getBlocks();
			IProcessingBlock prot_out = prot_blocks.get(prot_blocks.size() - 1);
			blocks.addAll(prot_blocks);
			blocks.addAll(ImmutableList.of(from, classify, alert, to1, to2, discard));
			connectors.addAll(prot_hdr_clas.getConnectors());
			connectors.addAll(ImmutableList.of(
					new Connector.Builder()
						.setSourceBlock(from)
						.setSourceOutputPort(0)
						.setDestBlock(classify)
						.build(),
					new Connector.Builder()
						.setSourceBlock(classify)
						.setSourceOutputPort(0)
						.setDestBlock(to1)
						.build(),
					new Connector.Builder()
						.setSourceBlock(classify)
						.setSourceOutputPort(1)
						.setDestBlock(prot_hdr_clas.getRoot())
						.build(),
					new Connector.Builder()
						.setSourceBlock(prot_out)
						.setSourceOutputPort(1)
						.setDestBlock(alert)
						.build(),
					new Connector.Builder()
						.setSourceBlock(prot_out)
						.setSourceOutputPort(0)
						.setDestBlock(to2)
						.build(),
					new Connector.Builder()
						.setSourceBlock(alert)
						.setSourceOutputPort(0)
						.setDestBlock(discard)
						.build()));

			IProcessingGraph graph = new ProcessingGraph.Builder()
				.setBlocks(blocks)
				.setConnectors(connectors)
				.setRoot(from)
				.build();

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
