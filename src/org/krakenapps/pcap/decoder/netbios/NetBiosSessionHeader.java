package org.krakenapps.pcap.decoder.netbios;

import org.krakenapps.pcap.util.Buffer;

public class NetBiosSessionHeader {
	private NetBiosSessionType type;
	private byte flags;
	private short length;
	public boolean isValid( ){
		if(isSessionMessage((byte)this.type.getValue()) || 
		isPositiveSessionResponse((byte)this.type.getValue())||
		isSessionRequest((byte)this.type.getValue())         ||
		isNegativeSessionResponse((byte)this.type.getValue())||
		isRetargetSessionResponse((byte)this.type.getValue())||
		isSessionKeepAlive((byte)this.type.getValue()))
			return true;
		else
			return false;
			
	}
	public boolean isSessionMessage(byte command){
		return (command & (byte)NetBiosSessionType.SessionMessage.getValue()) !=0;
	}
	public boolean isPositiveSessionResponse(byte command){
		return (command & (byte)NetBiosSessionType.PositiveSessionResponse.getValue()) !=0;
	}
	public boolean isSessionRequest(byte command){
		return (command & (byte)NetBiosSessionType.SessionRequest.getValue()) !=0;
	}
	public boolean isNegativeSessionResponse(byte command){
		return (command & (byte)NetBiosSessionType.NegativeSessionResponse.getValue()) !=0;
	}
	public boolean isRetargetSessionResponse(byte command){
		return (command & (byte)NetBiosSessionType.RetargetSessionResponse.getValue()) !=0;
	}
	public boolean isSessionKeepAlive(byte command){
		return (command & (byte)NetBiosSessionType.SessionKeepAlive.getValue()) !=0;
	}
	public NetBiosSessionType getType() {
		return type;
	}

	public void setType(NetBiosSessionType type) {
		this.type = type;
	}

	public byte getFlags() {
		return flags;
	}

	public void setFlags(byte flags) {
		this.flags = flags;
	}

	public short getLength() {
		return length;
	}

	public void setLength(short length) {
		this.length = length;
	}

	public static NetBiosSessionHeader parse(Buffer b) {
		NetBiosSessionHeader header = new NetBiosSessionHeader();
		header.setType(NetBiosSessionType.parse(b.get() & 0xff));
		header.setFlags(b.get());
		header.setLength(b.getShort());
		return header;

	}

	@Override
	public String toString() {
		return String.format("Session Header: type=%s, flags=%x, length=%d ",
				this.type, this.flags, this.length);
	}
}
