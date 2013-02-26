/*
 * Copyright 2012 Future Systems
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.krakenapps.pcap.decoder.wlan;

import org.krakenapps.pcap.decoder.ethernet.MacAddress;
import org.krakenapps.pcap.decoder.wlan.tag.WlanControlFrame;

public class WlanPowerSavePollFrame extends WlanControlFrame {
	private short associationId;
	private MacAddress bssid;
	private MacAddress transmitterAddress;

	public short getAssociationId() {
		return associationId;
	}

	public void setAssociationId(short associationId) {
		this.associationId = associationId;
	}

	public MacAddress getBssid() {
		return bssid;
	}

	public void setBssid(MacAddress bssid) {
		this.bssid = bssid;
	}

	public MacAddress getTransmitterAddress() {
		return transmitterAddress;
	}

	public void setTransmitterAddress(MacAddress transmitterAddress) {
		this.transmitterAddress = transmitterAddress;
	}

	@Override
	public String toString() {
		return "Power-Save poll [association id=" + associationId + ", bssid=" + bssid + ", transmitter address="
				+ transmitterAddress + "]";
	}

}
