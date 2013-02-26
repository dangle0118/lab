package org.krakenapps.pcap.decoder.tcp;

import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;

public class TcpLinkedList {
	public TcpLinkedList pnext;
	public Buffer data;
	public int Seq;
	public int LengthOfData;
	
	
	

}
