/*
 * Copyright 2010 NCHOVY
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
package org.krakenapps.pcap.decoder.udp;

import java.net.InetSocketAddress;
import java.util.Collection;

import org.krakenapps.pcap.Protocol;

public interface UdpProtocolMapper {
	Protocol map(UdpPacket packet);

	Collection<UdpProcessor> getUdpProcessors(Protocol protocol);

	void register(Protocol protocol, UdpProcessor processor);

	void unregister(Protocol protocol, UdpProcessor processor);

	void registerTemporaryMapping(InetSocketAddress sockAddr, Protocol protocol);

	void unregisterTemporaryMapping(InetSocketAddress sockAddr);

	@Deprecated
	UdpProcessor getUdpProcessor(Protocol protocol);

	@Deprecated
	void unregister(Protocol protocol);
}
