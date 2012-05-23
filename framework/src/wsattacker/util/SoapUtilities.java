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

package wsattacker.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.Node;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class SoapUtilities {
	private static Logger log = Logger.getLogger(SoapUtilities.class);
	
	public static final String SOAP_11_NAMESPACE_URL = "http://schemas.xmlsoap.org/soap/envelope/";
	public static final String SOAP_12_NAMESPACE_URL = "http://www.w3.org/2003/05/soap-envelope";
	
	/**
	 * Converts an XML String to a javax.xml.soap.SOAPMessage
	 * Detects SOAP Protocol Version 1.1 and 1.2 via SOAP Namespace
	 * @param soapString
	 * @return
	 * @throws SOAPException
	 */
	public static SOAPMessage stringToSoap(String soapString) throws SOAPException {
		byte[] bytes;
		try {
			bytes = soapString.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			log.fatal("### Error - this should never happen: " + e.getMessage());
			bytes = "".getBytes();
		}
		String protocol;
		// detecting soap protocoll version
		if(soapString.contains(SOAP_11_NAMESPACE_URL)) {
			protocol = javax.xml.soap.SOAPConstants.SOAP_1_1_PROTOCOL;
		} else if (soapString.contains(SOAP_12_NAMESPACE_URL)) {
			protocol = javax.xml.soap.SOAPConstants.SOAP_1_2_PROTOCOL;
		} else {
			throw new SOAPException("Could't not detect SOAP protocol Version");
		}
		SOAPMessage sm;
		try {
			// create new SOAPMessage with null header and xml content
			sm = MessageFactory.newInstance(protocol).createMessage(null, new ByteArrayInputStream(bytes));
		} catch (IOException e) {
			e.printStackTrace();
			log.fatal("### Error - this should never happen: " + e.getMessage());
			sm = MessageFactory.newInstance().createMessage(); // return new empty message
		}
		return sm;
	}
	
	/**
	 * Converts a javax.xml.soap.SOAPElement to a String
	 * Can be used for soapUI requests
	 * Be carefull: To convert a SOAPMessage sm, you must use
	 *				sm.getSOAPPart().getEnvelope();
	 * @param element
	 * @return
	 */
	public static String soapToString(SOAPElement element) {
		// use the dom hepler function
		return domToString(element.getOwnerDocument());
	}
	
	/**
	 * Converts a String to a DOM.
	 * Sometimes, you might prefer DOM to SOAPElement.
	 * No namespace prefixes are used by default.
	 * @param xmlString
	 * @return
	 * @throws SAXException
	 */
	public static Document stringToDom(String xmlString) throws SAXException {
		return stringToDom(xmlString, false);
	}
	
	/**
	 * Converts a String to a DOM.
	 * Sometimes, you might prefer DOM to SOAPElement.
	 * @param xmlString
	 * @param useNamespaces : Should the returned Document contain namespace prefixes?
	 * @return
	 * @throws SAXException
	 */
	public static Document stringToDom(String xmlString, boolean useNamespaces) throws SAXException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(useNamespaces);
		StringReader reader = new StringReader(xmlString);
		InputSource input = new InputSource(reader);
		DocumentBuilder builder;
		try {
			builder = factory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			log.fatal("### Error - this should never happen: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
		Document dom;
		try {
			dom = builder.parse(input);
		} catch (IOException e) {
			log.fatal("### Error - this should never happen: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
		return dom;
	}
	
	/**
	 * Converts a DOM to a String
	 * @param domDoc
	 * @return
	 */
	public static String domToString(Document domDoc) {
		StringWriter output = new StringWriter();
		Transformer transformer = null;
		try {
			transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			transformer.transform(new DOMSource(domDoc), new StreamResult(output));
		} catch (TransformerConfigurationException e) {
			log.fatal("### Error - Misconfigured Transformer Configuration, this should never happen: " + e.getMessage());
			e.printStackTrace();
		} catch (TransformerFactoryConfigurationError e) {
			log.fatal("### Error - Misconfigured Transformer Factory, this should never happen: " + e.getMessage());
			e.printStackTrace();
		} catch (TransformerException e) {
			log.fatal("### Error - Illegal Input, this should never happen: " + e.getMessage());
			e.printStackTrace();
		}
	    return output.toString();
	}
	
	/**
	 * Finds all SOAP Childs of an SOAPElement (non recursive)
	 * This is useful, as getChildElements() will also contain Text Nodes.
	 * This method only returns instances of SOAPElement
	 * @param ele
	 * @param namespace: if null, all childs will be returned
	 * @return
	 */
	public static List<SOAPElement> getSoapChilds(SOAPElement ele, QName name) {
		List<SOAPElement> list = new ArrayList<SOAPElement>();
		Iterator<?> ei;
		if (name == null) {
			ei = ele.getChildElements();
		} else {
			ei = ele.getChildElements(name);
		}
		while(ei.hasNext()) {
			Object o = ei.next();
			if (o instanceof SOAPElement ) {
				SOAPElement e = (SOAPElement) o;
				log.trace("Found Child Element // " + e.getNodeName());
				list.add(e);
			}
		}
		return list;
		
	}
	
	/**
	 * Finds all SOAP Childs of an SOAPElement (non recursive)
	 * This is useful, as getChildElements() will also contain Text Nodes.
	 * This method only returns instances of SOAPElement
	 * @param ele
	 * @return
	 */
	public static List<SOAPElement> getSoapChilds(SOAPElement ele) {
		return getSoapChilds(ele, null);
	}
	
	/**
	 * Finds recursive all leafs of a SOAPElement as they are expected
	 * to need text content.
	 * Excludes elements of soap-env and soap namespace (Envelop, Header Body)
	 * @param ele
	 * @return
	 */
	public static List<SOAPElement> inputNeeded(SOAPElement ele) {
		List<SOAPElement>  l = new ArrayList<SOAPElement>();
		log.trace("Starting Input-Needed Lookup for " + ele.getNodeName());
		inputNeeded(ele, l);
		log.trace("Input-Needed Lookup done: " + l);
		
		return l;
	}
	
	private static void inputNeeded(SOAPElement ele, List<SOAPElement> l) {
		// input is needed for leafs or for existing text-nods
		if (!ele.hasChildNodes() || (ele.getChildNodes().getLength() == 1 && (ele.getFirstChild().getNodeType() == Node.TEXT_NODE) )) {
			// check if element is a special element that should never get input
			String namespace = ele.getNamespaceURI();
			// only add to list if element has no namspace or namespace is no soap namespace
			if(namespace == null || (!namespace.equals(SOAP_11_NAMESPACE_URL) && !namespace.equals(SOAP_12_NAMESPACE_URL))) {
				log.trace("Adding node " + ele.getNodeName());
				l.add(ele);
			}
		}
		for(SOAPElement e : getSoapChilds(ele)) {
			inputNeeded(e , l);
		}
	}
	
	/**
	 * Returns a list of all namespaces below an element (recursive)
	 * @param ele
	 * @return
	 */
	public static Map<String,String> allNamespaces(SOAPElement ele) {
		Map<String,String> nsList = new TreeMap<String, String>();
		log.trace("Starting Namespace Lookup in " + ele.getNodeName());
		allNamespaces(ele, nsList);
		log.trace("Namespace Lookup done: " + nsList);
		return nsList;
	}
	
	private static void allNamespaces(SOAPElement ele, Map<String,String> nsList) {
		Iterator<?> i;
		// Loop through namespaces
		i = ele.getNamespacePrefixes();
		while(i.hasNext()){
			String prefix = (String) i.next();
			String uri = ele.getNamespaceURI(prefix);
			log.trace("Found Namespace // " + prefix + ":" + uri);
			nsList.put(prefix, uri);
		}
		// Loop through childs
		for(SOAPElement e : getSoapChilds(ele)) {
			allNamespaces(e , nsList);
		}
	}
	
	/**
	 * Returns a list of all parents of a SOAPElement
	 * The first element of the list is the father of e, 
	 * the second the grand-father and so on.
	 * Last element is always the root.
	 * @param e
	 * @return
	 */
	public static List<SOAPElement> getParents(SOAPElement e) {
		// searching all parent nodes
    	List<SOAPElement> parents = new ArrayList<SOAPElement>();
    	SOAPElement zwerg = e.getParentElement();
    	while (zwerg != null) {
    		parents.add(zwerg);
    		zwerg = zwerg.getParentElement();
    	}
    	return parents;
	}
	
	/**
	 * Returns the root element of e
	 * @param e
	 * @return
	 */
	public static SOAPElement getRoot(SOAPElement e) {
		List<SOAPElement> parents = getParents(e);
		int size = parents.size();
		if (size > 0) {
			return parents.get(size-1);
		}
		else {
			return e;
		}
	}
}
