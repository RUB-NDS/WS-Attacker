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

package wsattacker.plugin.wsAddressingSpoofing.option;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.log4j.Logger;

import wsattacker.main.composition.plugin.option.AbstractOptionChoice;
import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.composition.plugin.option.AbstractOptionVarchar;

public class OptionIpChooser extends AbstractOptionChoice {

	private static final String URL = new String("http://checkip.dyndns.org");
	private static final String REGEX = new String("[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}");
	
	public static final String AUTO = "Detect your IP via " + URL;
	public static final String MANUAL = "Edit settings below as you like";
	
	private static Logger log = Logger.getLogger(OptionIpChooser.class);
	private static final long serialVersionUID = 1L;
	
	List<String> choices;
	String selected;
	AbstractOptionVarchar url;
	AbstractOptionInteger port;
	
	public OptionIpChooser(String name, String description, AbstractOptionVarchar url, AbstractOptionInteger port) {
		super(name, description);
		choices = new ArrayList<String>();
		choices.add(MANUAL);
		choices.add(AUTO);
		this.url = url;
		this.port = port;

		setChoice(AUTO);
	}

	@Override
	public List<String> getChoices() {
		return choices;
	}

	@Override
	public boolean setChoice(String value) {
		if(isValid(value)) {
			selected = value;
			if (selected.equals(AUTO) ) {
				updateUrl();
			}
			notifyValueChanged();
			return true;
		}
		return false;
	}

	@Override
	public boolean parseValue(String value) {
		return setChoice(value);
	}
	
	@Override
	public boolean setChoice(int index) {
		if(isValid(index)) {
			return setChoice(choices.get(index));
		}
		return false;
	}

	@Override
	public boolean isValid(String value) {
		return choices.contains(value);
	}

	@Override
	public boolean isValid(int choice) {
		return (choice >= 0 && choice < choices.size());
	}

	@Override
	public int getChoice() {
		return choices.indexOf(selected);
	}
	
	@Override
	public String getValueAsString() {
		return selected;
	}
	
	public String detectIP() {
		String ip = null;
		
		// fetch HTML

	    // Create an instance of HttpClient.
	    HttpClient client = new HttpClient();

	    // Create a method instance.
	    GetMethod method = new GetMethod(URL);
	    
	    // Provide custom retry handler is necessary
//	    method.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, new DefaultHttpMethodRetryHandler(3, false));
	    String html;
	    try {
	      // Execute the method.
	      int statusCode = client.executeMethod(method);

	      if (statusCode != HttpStatus.SC_OK) {
	        log.error("Could not fetch website to detect IP");
	        return null;
	      }

	      // Read the response body.
	      byte[] responseBody = method.getResponseBody();

	      // Deal with the response.
	      // Use caution: ensure correct character encoding and is not binary data
	      html = new String(responseBody);

	    } catch (HttpException e) {
	        log.error("Could not fetch website to detect IP");
	        return null;
	    } catch (IOException e) {
	        log.error("Could not fetch website to detect IP");
	        return null;
	    } finally {
	      // Release the connection.
	      method.releaseConnection();
	    } 
	    
	    // extract ip from html code
	    
	    Pattern p = Pattern.compile(REGEX);
	    Matcher m = p.matcher(html);

	    // first match is used
	    m.find();
	    ip = html.substring(m.start(), m.end());
	    
	    return ip;

	}
	
	private void updateUrl() {
		String ip = detectIP();
		if(ip == null) {
			url.setValue("Could not detect your IP");
		} else {
			url.setValue("http://" + ip + ":" + port.getValue());
		}
		setChoice(MANUAL);
	}

}
