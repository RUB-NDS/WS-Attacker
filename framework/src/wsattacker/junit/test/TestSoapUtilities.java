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

package wsattacker.junit.test;


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static wsattacker.util.SoapUtilities.allNamespaces;
import static wsattacker.util.SoapUtilities.getParents;
import static wsattacker.util.SoapUtilities.getSoapChilds;
import static wsattacker.util.SoapUtilities.inputNeeded;
import static wsattacker.util.SoapUtilities.soapToString;
import static wsattacker.util.SoapUtilities.stringToSoap;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Test;

import wsattacker.util.SoapUtilities;

public class TestSoapUtilities {
	private static final String MESSAGE = "" +
			"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns1=\"http://sn1.com\">" +
			"   <soapenv:Header>" +
			"    <ns1:double/>" +
			"    <ns1:ha>Header A</ns1:ha>" +
			"    <ns1:hb/>" +
			"    <ns1:hc></ns1:hc>" +
			"    <ns1:double/>" +
			"   </soapenv:Header>" +
			"   <soapenv:Body xmlns:ns2=\"http://ns2.com\">" +
			"      <ns1:ServiceOperation>" +
			"         <ns1:ba>Body A</ns1:ba>" +
			"         <ns1:c><ns2:d><ns3:e xmlns:ns3=\"http://ns3.com\">Body D</ns3:e></ns2:d></ns1:c>" +
			"         <a><b/></a>" +
			"      </ns1:ServiceOperation>" +
			"   </soapenv:Body>" +			
			"</soapenv:Envelope>";
	
	@Test
	public void testStringToSoapCorrect() throws Exception {
		String msg = new String(MESSAGE);
		stringToSoap(msg);
	}
	
	@Test(expected = SOAPException.class)
	public void testStringToSoapBadFormated() throws Exception {
		String msg = new String(MESSAGE).substring(0, MESSAGE.length()-1); // delete last ">" char
		SOAPMessage soap = stringToSoap(msg);
		System.out.println(soapToString(soap.getSOAPPart().getEnvelope()));
	}
	
	@Test 
	public void testGetChilds() throws Exception {
		String msg = new String(MESSAGE);
		SOAPMessage soap = stringToSoap(msg);
		
		List<SOAPElement> childs;
		String childname;
		
		childs = getSoapChilds(soap.getSOAPBody());
		childname = "ns1:ServiceOperation";
		assertTrue("Should be only one child.", childs.size() == 1);
		assertTrue(String.format("Wrong Child (%s != %s)", childs.get(0).getNodeName(), childname), childs.get(0).getNodeName().equals(childname));
		
		childs = getSoapChilds(soap.getSOAPHeader());
		assertTrue("Header should have 5 childs", 5 == childs.size());
		
		childs = getSoapChilds(soap.getSOAPHeader(), soap.getSOAPHeader().createQName("double", "ns1"));
		childname = "ns1:double";
		assertTrue("Should found two childs.", childs.size() == 2);
		for(int i=0; i<=1; ++i) {
			assertTrue(String.format("Wrong Child (%s != %s)", childs.get(i).getNodeName(), childname), childs.get(i).getNodeName().equals(childname));
		}
		
	}
	
	@Test
	public void testGetNamespaces() throws Exception {
		String msg = new String(MESSAGE);
		SOAPMessage soap = stringToSoap(msg);
		Map<String,String> namespaces = allNamespaces(soap.getSOAPPart().getEnvelope());

		String[] keys = {"soapenv","ns1","ns2","ns3"};
		String[] values = {"http://schemas.xmlsoap.org/soap/envelope/", "http://sn1.com", "http://ns2.com", "http://ns3.com"};
		for(String key : keys) {
			assertTrue("Does not contain namespace " + key, namespaces.containsKey(key));
		}
		for(int i=0;i<keys.length;++i) {
			String prefix = keys[i];
			String uri = values[i];
			assertTrue(String.format("Wrong Namspace, shoult be %s=%s",prefix,uri), namespaces.get(prefix).equals(uri));
		}
	}
	
	@Test
	public void testGetInputNeeded() throws Exception {
		String msg = new String(MESSAGE);
		SOAPMessage soap = stringToSoap(msg);
		Logger.getLogger(SoapUtilities.class).setLevel(Level.ALL);
		List<SOAPElement> inputNeeded = inputNeeded(soap.getSOAPPart().getEnvelope());
		
		// expected elements
		List<String> elementNames = new ArrayList<String>();
		elementNames.add("ns1:ha");
		elementNames.add("ns1:hb");
		elementNames.add("ns1:hc");
		elementNames.add("ns1:ba");
		elementNames.add("ns3:e");
		elementNames.add("ns1:double");
		elementNames.add("ns1:double");
		elementNames.add("b");
		
		int shouldBeFound = elementNames.size();
		
		for(SOAPElement ele : inputNeeded) {
			String name = ele.getNodeName();
			assertTrue("Element not contained: " + name,elementNames.contains(name));
			elementNames.remove(name);
		}

		assertFalse(String.format("Found more than possible, Expected %d, Found %d", shouldBeFound, inputNeeded.size()), shouldBeFound > inputNeeded.size());
		assertTrue("Not all Elements found: " + elementNames,elementNames.isEmpty());
		
	}
	
	@Test
	public void testGetParents() throws Exception {
		String msg = new String(MESSAGE);
		SOAPMessage soap = stringToSoap(msg);
		SOAPElement ele = getSoapChilds(getSoapChilds(getSoapChilds(soap.getSOAPBody()).get(0)).get(1)).get(0);
		assertTrue(ele.getNodeName().equals("ns2:d"));
		List<SOAPElement> testParents = getParents(ele);
		String[] trueParents = {"ns1:c","ns1:ServiceOperation","soapenv:Body","soapenv:Envelope"};
		for(int i=0; i<testParents.size(); ++i) {
			String trueName = trueParents[i];
			String testName = testParents.get(i).getNodeName();
			assertTrue(String.format("Wrong Parent, got %s, but expected %s", testName, trueName), trueName.equals(testName));
		}
	}
	

}
