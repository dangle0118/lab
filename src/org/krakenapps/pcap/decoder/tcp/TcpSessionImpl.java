package org.krakenapps.pcap.decoder.tcp;

import java.util.concurrent.atomic.AtomicInteger;

import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.krakenapps.pcap.decoder.tcp.TcpLinkedList;


public class TcpSessionImpl implements TcpSession {
	private static AtomicInteger LAST_ID = new AtomicInteger(1);
	private int id;

	public TcpLinkedList StoreDataFromServer;
	public TcpLinkedList StoreDataFromClient;
	
	
	private TcpSessionKey key;

	private TcpHost client;
	private TcpHost server;

	private int clientFirstSeq;
	private int serverFirstSeq;

	private TcpStreamOption clientStreamOption;
	private TcpStreamOption serverStreamOption;

	private int clientFlags;
	private int serverFlags;

	private TcpState clientState;
	private TcpState serverState;

	private boolean isRegisterProtocol;
	private Protocol protocol;

	private Buffer clientSent;
	private Buffer serverSent;

	private WaitQueue clientQueue;
	private WaitQueue serverQueue;

	private ApplicationLayerMapper l7Mapper;

	private int packetCountAfterFin = 0;
	private int firstFinSeq = -1;
	private int firstFinAck = -1;

	public TcpSessionImpl(TcpProtocolMapper mapper) {
		id = LAST_ID.getAndIncrement();
		key = null;

		clientStreamOption = TcpStreamOption.NORMAL;
		serverStreamOption = TcpStreamOption.NORMAL;
		
		StoreDataFromServer = new TcpLinkedList();
		StoreDataFromClient = new TcpLinkedList();
		

		clientState = TcpState.LISTEN;
		serverState = TcpState.LISTEN;

		clientSent = new ChainBuffer();
		serverSent = new ChainBuffer();

		clientQueue = new WaitQueue();
		serverQueue = new WaitQueue();

		l7Mapper = new ApplicationLayerMapper(mapper);
	}

	public int getId() {
		return id;
	}

	public TcpSessionKey getKey() {
		return key;
	}

	public void setKey(TcpSessionKey key) {
		this.key = key;
	}

	public TcpHost getClient() {
		return client;
	}

	public void createClient(TcpPacket packet) {
		client = new TcpHost(packet);
	}

	public TcpHost getServer() {
		return server;
	}

	public void createServer(TcpPacket packet) {
		server = new TcpHost(packet);
	}

	/* constraint: one-time called */
	public void setClientFirstSeq(int clientFirstSeq) {
		this.clientFirstSeq = clientFirstSeq;
	}

	public int retRelativeClientSeq(int sequenceNumber) {
		return (sequenceNumber - clientFirstSeq);
	}

	/* constraint: one-time called */
	public void setServerFirstSeq(int serverFirstSeq) {
		this.serverFirstSeq = serverFirstSeq;
	}

	public int retRelativeServerSeq(int sequenceNumber) {
		return (sequenceNumber - serverFirstSeq);
	}

	public TcpStreamOption getClientStreamOption() {
		return clientStreamOption;
	}

	public void setClientStreamOption(TcpStreamOption clientStreamOption) {
		this.clientStreamOption = clientStreamOption;
	}

	public TcpStreamOption getServerStreamOption() {
		return serverStreamOption;
	}

	public void setServerStreamOption(TcpStreamOption serverStreamOption) {
		this.serverStreamOption = serverStreamOption;
	}

	public int getClientFlags() {
		return clientFlags;
	}

	public void setClientFlags(int clientFlags) {
		this.clientFlags = clientFlags;
	}

	public int getServerFlags() {
		return serverFlags;
	}

	public void setServerFlags(int serverFlags) {
		this.serverFlags = serverFlags;
	}

	public TcpState getClientState() {
		return clientState;
	}

	public void setClientState(TcpState clientState) {
		this.clientState = clientState;
	}

	public TcpState getServerState() {
		return serverState;
	}

	public void setServerState(TcpState serverState) {
		this.serverState = serverState;
	}

	public boolean isRegisterProtocol() {
		return isRegisterProtocol;
	}

	public void setRegisterProtocol(boolean isRegisterProtocol) {
		this.isRegisterProtocol = isRegisterProtocol;
	}

	public void registerProtocol(Protocol protocol) {
		this.protocol = protocol;
	}

	public void unregisterProtocol(Protocol protocol) {
		if (this.protocol == protocol)
			this.protocol = null;
	}

	public Protocol getProtocol() {
		return protocol;
	}

	public void storeToClientSent(Buffer data) {
		clientSent.addLast(data);
	}

	public void storeToServerSent(Buffer data) {
		serverSent.addLast(data);
	}

	public void checkReassemble(){
		TcpLinkedList temp = StoreDataFromServer.pnext;
		boolean check  = true;
		
		while ( (temp != null) && (temp.pnext != null))
		{
			if ( temp.Seq + temp.LengthOfData != temp.pnext.Seq )
			{
				System.out.println("Error: a gap between Seq " + temp.Seq + " and " + temp.pnext.Seq);
				check = false;
			}
			temp = temp.pnext;
		}
		if ( check == true)
			System.out.println("Reassemble completed. No error!");
	}
	
	
	public void pushToClient(int Seq,Buffer data) { 
		
		
		TcpLinkedList temp = StoreDataFromServer.pnext;
		int LengthOfData = data.readableBytes();
		if ( temp == null)
		{
			temp = new TcpLinkedList();
			temp.data = data;
			temp.Seq = Seq;
			temp.LengthOfData = data.readableBytes();
			temp.pnext = null;	
			StoreDataFromServer.pnext = temp;
			return;
		}
		
		while(temp != null)
		{
			if ((temp.Seq + temp.LengthOfData) <= Seq)
			{
//XXXXX
//      XXXXX
				if ( temp.pnext == null)
				{
					TcpLinkedList temp2 = new TcpLinkedList();
					temp2.Seq = Seq;
					temp2.LengthOfData = LengthOfData;
					temp2.pnext = temp.pnext;
					temp2.data = data;
					temp.pnext = temp2;
					return;
				}
				else if ( temp.pnext.Seq <= Seq)
					temp = temp.pnext;
					continue;
			}
//XXXXXX
//    XXXXX
			if ( (temp.Seq < Seq )&& (temp.Seq + temp.LengthOfData > Seq))
			{
				int remain = (temp.Seq + temp.LengthOfData) - Seq;
				Seq = temp.Seq + temp.LengthOfData;
				int readable = data.readableBytes();
				if ( readable < remain)
					return;
				readable = readable - remain;
				data.skip(readable);
				data.discardReadBytes();	
				LengthOfData = readable;
				
			}
//       xxxx
//xxxxx
			if ( temp.pnext != null)
			{	
			if (( Seq + LengthOfData < temp.pnext.Seq))
			{
				TcpLinkedList temp2 = new TcpLinkedList();
				temp2.Seq = Seq;
				temp2.LengthOfData = LengthOfData;
				temp2.pnext = temp.pnext;
				temp2.data = data;
				temp.pnext = temp2;
				return;
			}
			
//    XXXX
//XXXXXX
			if ( Seq + LengthOfData >temp.pnext.Seq)
			{
				LengthOfData = (Seq + LengthOfData) - ((Seq + LengthOfData) - temp.pnext.Seq);			
				TcpLinkedList temp2 = new TcpLinkedList();
				temp2.Seq = Seq;
				temp2.LengthOfData = LengthOfData;
				temp2.data = data;
				temp2.pnext = temp.pnext;
				temp.pnext = temp2;
				return;
			}
			}
			else
			{
				TcpLinkedList temp2 = new TcpLinkedList();
				temp2.Seq = Seq;
				temp2.LengthOfData = LengthOfData;
				temp2.pnext = temp.pnext;
				temp2.data = data;
				temp.pnext = temp2;
				return;
			}
				
		}
		
		l7Mapper.sendToApplicationLayer(protocol, key, TcpDirection.ToClient, data);
	}
	
	public void pushToServer(int Seq, Buffer data) { 
		
		TcpLinkedList temp = StoreDataFromClient.pnext;
		int LengthOfData = data.readableBytes();
		if ( temp == null)
		{
			temp = new TcpLinkedList();
			temp.data = data;
			temp.Seq = Seq;
			temp.LengthOfData = data.readableBytes();
			temp.pnext = null;		
			StoreDataFromClient.pnext = temp;
			return;
		}
		
		while(temp != null)
		{
			if ((temp.Seq + temp.LengthOfData) <= Seq)
			{
//XXXXX
//      XXXXX
				if ( temp.pnext == null)
				{
					TcpLinkedList temp2 = new TcpLinkedList();
					temp2.Seq = Seq;
					temp2.LengthOfData = LengthOfData;
					temp2.pnext = temp.pnext;
					temp2.data = data;
					temp.pnext = temp2;
					return;
				}
				else if ( temp.pnext.Seq <= Seq)
					temp = temp.pnext;
					continue;
			}
//XXXXXX
//    XXXXX
			if ( (temp.Seq < Seq )&& (temp.Seq + temp.LengthOfData > Seq))
			{
				int remain = (temp.Seq + temp.LengthOfData) - Seq;
				Seq = temp.Seq + temp.LengthOfData;
				int readable = data.readableBytes();
				if ( readable < remain)
					return;
				readable = readable - remain;
				data.skip(readable);
				data.discardReadBytes();	
				LengthOfData = readable;
				
			}
//       xxxx
//xxxxx
			
			if ( Seq + LengthOfData < temp.pnext.Seq)
			{
				TcpLinkedList temp2 = new TcpLinkedList();
				temp2.Seq = Seq;
				temp2.LengthOfData = LengthOfData;
				temp2.pnext = temp.pnext;
				temp2.data = data;
				temp.pnext = temp2;
				return;
			}
			
//    XXXX
//XXXXXX
			if ( Seq + LengthOfData >temp.pnext.Seq)
			{
				LengthOfData = (Seq + LengthOfData) - ((Seq + LengthOfData) - temp.pnext.Seq);			
				TcpLinkedList temp2 = new TcpLinkedList();
				temp2.Seq = Seq;
				temp2.LengthOfData = LengthOfData;
				temp2.data = data;
				temp2.pnext = temp.pnext;
				temp.pnext = temp2;
				return;
			}
		}
	
		l7Mapper.sendToApplicationLayer(protocol, key, TcpDirection.ToServer, data);
		
		
	}

	public void pushToClientSack(Buffer data) {
		l7Mapper.sendToApplicationLayer(protocol, key, TcpDirection.ToServer, data);
	}

	public void pushToServerSack(Buffer data) {
		l7Mapper.sendToApplicationLayer(protocol, key, TcpDirection.ToClient, data);
	}

	public WaitQueue getClientQueue() {
		return clientQueue;
	}

	public WaitQueue getServerQueue() {
		return serverQueue;
	}

	public int getPacketCountAfterFin() {
		return packetCountAfterFin;
	}

	public void setPacketCountAfterFin(int packetCountAfterFin) {
		this.packetCountAfterFin = packetCountAfterFin;
	}

	public int getFirstFinSeq() {
		return firstFinSeq;
	}

	public void setFirstFinSeq(int firstFinSeq) {
		this.firstFinSeq = firstFinSeq;
	}

	public int getFirstFinAck() {
		return firstFinAck;
	}

	public void setFirstFinAck(int firstFinAck) {
		this.firstFinAck = firstFinAck;
	}

	public void doEstablish(TcpSessionTable sessionTable, TcpSessionImpl session, TcpPacket packet, TcpStateUpdater stateUpdater) {
		sessionTable.doEstablish(session, packet, stateUpdater);
	}

	public void close(TcpSessionTable sessionTable, TcpSessionImpl session, TcpPacket packet) {
		sessionTable.close(packet);
	}

	public void setRelativeNumbers(TcpPacket packet) {
		switch (packet.getFlags()) {
		case TcpFlag.SYN:
			packet.setRelativeSeq(0);
			break;
		case TcpFlag.SYN + TcpFlag.ACK:
			packet.setRelativeSeq(0);
			packet.setRelativeAck(1);
			break;
		default:
			if (packet.getDirection() == TcpDirection.ToServer) {
				packet.setRelativeSeq(retRelativeClientSeq(packet.getSeq()));
				packet.setRelativeAck(retRelativeServerSeq(packet.getAck()));

			} else {
				packet.setRelativeSeq(retRelativeServerSeq(packet.getSeq()));
				packet.setRelativeAck(retRelativeClientSeq(packet.getAck()));
			}
			break;
		}
	}
}