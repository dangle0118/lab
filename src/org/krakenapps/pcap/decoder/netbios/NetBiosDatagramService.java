package org.krakenapps.pcap.decoder.netbios;

import org.krakenapps.pcap.decoder.netbios.rr.DatagramErrorData;
import org.krakenapps.pcap.decoder.netbios.rr.DatagramHeader;
import org.krakenapps.pcap.decoder.netbios.rr.DirectBroadcastData;
import org.krakenapps.pcap.decoder.netbios.rr.DirectBroadcastHeader;
import org.krakenapps.pcap.decoder.netbios.rr.ErrorRRHeader;
import org.krakenapps.pcap.decoder.netbios.rr.QueryData;
import org.krakenapps.pcap.util.Buffer;

public class NetBiosDatagramService {
	public NetBiosDatagramPacket parse(Buffer b) {
		DatagramHeader header = null;
		DatagramData data = null;
		
		byte type = b.get();

		switch (NetBiosDatagramType.parse(type & 0xff)) {
		case DirectUniqueDatagram:
		case DirectGroupDatagram:
		case BroadcastDatagram:
			header = DirectBroadcastHeader.parse(b);
			data = DirectBroadcastData.parse(b);
			break;
		case DatagramError:
			header = ErrorRRHeader.parse(b);
			data = DatagramErrorData.parse(b);
			break;
		case DatagramQueryRequest:
		case DatagramPositiveQueryResponse:
		case DatagramNegativeQueryResponse:
			header = ErrorRRHeader.parse(b);
			data = QueryData.parse(b);
			break;
		default:
			throw new IllegalArgumentException(
					"invalid netbios datagram packet type: " + type);
		}
		
		return new NetBiosDatagramPacket(header, data);
	}
}
