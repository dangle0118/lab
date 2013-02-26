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
package org.krakenapps.pcap.decoder.http;

import org.krakenapps.pcap.util.Buffer;
import java.net.InetAddress;

/**
 * @author mindori
 */
public interface HttpProcessor {
	void onRequest(HttpRequest req, InetAddress ClientIp, InetAddress ServerIp);
	
	void onResponse(HttpRequest req, HttpResponse resp, InetAddress ClientIp, InetAddress ServerIp);
	
	void onMultipartData(Buffer buffer);
}
