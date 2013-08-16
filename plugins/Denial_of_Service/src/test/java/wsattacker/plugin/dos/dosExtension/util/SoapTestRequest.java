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
package wsattacker.plugin.dos.dosExtension.util;

import com.eviware.soapui.impl.WsdlInterfaceFactory;
import com.eviware.soapui.impl.wsdl.WsdlInterface;
import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.support.SoapUIException;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import wsattacker.util.SoapUtilities;

/**
 * A simple SoapMessage Test document
 *
 */
public class SoapTestRequest {

    Document requestDoc;
    String requestString;
    WsdlRequest requestWsdlRequest;
    String pathToLocalWsdl;

    public SoapTestRequest() {

	// new Wsdl Project
	WsdlProject project = null;
	try {
	    project = new WsdlProject();
	} catch (XmlException ex) {
	    Logger.getLogger(SoapTestRequest.class.getName()).log(Level.SEVERE, null, ex);
	} catch (IOException ex) {
	    Logger.getLogger(SoapTestRequest.class.getName()).log(Level.SEVERE, null, ex);
	} catch (SoapUIException ex) {
	    Logger.getLogger(SoapTestRequest.class.getName()).log(Level.SEVERE, null, ex);
	}
	
	// Create a copy of WSDL file on tmp folder of local filesystem
	pathToLocalWsdl = createLocalWsdl();

	// new Interface from local WSDL
	WsdlInterface iface = null;
	try {
	    iface = WsdlInterfaceFactory.importWsdl(project, pathToLocalWsdl, true)[0];
	} catch (SoapUIException ex) {
	    Logger.getLogger(SoapTestRequest.class.getName()).log(Level.SEVERE, null, ex);
	}

	// get Operation and create Requests for Operations...
	WsdlOperation operation = (WsdlOperation) iface.getOperationAt(0);
	requestWsdlRequest = operation.addNewRequest("MyTestRequest");
	requestWsdlRequest.setRequestContent(operation.createRequest( true ));
	requestString = requestWsdlRequest.getRequestContent();
	try {
	    requestDoc = SoapUtilities.stringToDom(requestString);
	} catch (SAXException e1) {
	    // TODO Auto-generated catch block
	    e1.printStackTrace();
	}
    }
    
    /**
     * Creates copy of bundled WSDL in local tmp folder.
     * This way clean WsdlRequests can be build from SoapUi for testing
     * @return 
     */
    public String createLocalWsdl(){
	String fullFilePath;
	String property = "java.io.tmpdir";
	String tempDir = System.getProperty(property);
	System.out.println("OS current temporary directory is " + tempDir);
	
	// make Folders
	File resultDir = new File(tempDir + "/wsattackerdos");
	if (!resultDir.exists()) { // if the directory does not exist, create it
	    resultDir.mkdir();
	}
	fullFilePath = resultDir + "/genericRequest.wsdl";

	// copy Helpfile from .jar to resultDir
	URL inputUrl;
	inputUrl = getClass().getResource("/TestWsdls/genericRequest.wsdl");
	File dest = new File(fullFilePath);
	try {
	    FileUtils.copyURLToFile(inputUrl, dest);
	} catch (Exception e) {
	    e.printStackTrace();
	}
	
	return fullFilePath;
    }

    public Document getDocument() {
	return requestDoc;
    }

    public String getDocumentString() {
	return requestString;
    }
    
    public WsdlRequest getWsdlRequest() {
	return requestWsdlRequest;
    }    
}
