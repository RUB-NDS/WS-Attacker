/*
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2010  Christian Mainka
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package wsattacker.plugin.wsAddressingSpoofing.util;

import java.io.*;
import java.net.InetSocketAddress;

import com.eviware.soapui.SoapUI;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class MicroHttpServer {
	private int port;
	private HttpServer server;
	private boolean incomingRequest;
	private String requestBody;

	public MicroHttpServer(int port) {
		this.port = port;
		this.incomingRequest = false;
		this.requestBody = null;
	}

	public int getPort() {
		return port;
	}
	
	public boolean hasIncomingRequest() {
		return incomingRequest;
	}
	
	public String getRequestBody() {
		return requestBody;
	}
	
	public void resetIncomingRequest() {
		this.incomingRequest = false;
		this.requestBody = null;
	}
	
	public HttpServer getServer() {
		return server;
	}

	public void start() {
		InetSocketAddress addr = new InetSocketAddress(getPort());
		try {
			server = HttpServer.create(addr, 0);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
		
		server.createContext("/", new HttpHandler() {

			@Override
			public void handle(HttpExchange exchange) throws IOException {
				String line;
				InputStream is = exchange.getRequestBody();
				BufferedReader in = new BufferedReader(
						new InputStreamReader(is));
				StringBuffer buffer = new StringBuffer();
				while ((line = in.readLine()) != null) {
					buffer.append(line);
				}
				requestBody = buffer.toString();
				incomingRequest = true;
				exchange.sendResponseHeaders(200, 0); // send OK to the server
				exchange.close();
			}
		});
		server.setExecutor(SoapUI.getThreadPool());
		server.start();
	}

	/**
	 * aborts the running server
	 */
	public void stop() {
		try {
			// closing server
			server.stop(1);
		} catch (Exception e) {
			// only for safety
		}
	}
}
