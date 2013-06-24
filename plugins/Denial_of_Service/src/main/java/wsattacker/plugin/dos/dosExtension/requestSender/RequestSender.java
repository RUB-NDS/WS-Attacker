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
package wsattacker.plugin.dos.dosExtension.requestSender;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.WsdlSubmit;
import com.eviware.soapui.impl.wsdl.WsdlSubmitContext;
import com.eviware.soapui.impl.wsdl.support.soap.SoapUtils;
import com.eviware.soapui.model.iface.Request;
import java.awt.EventQueue;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.soap.SOAPException;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpConnectionManager;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.params.HttpParams;
import org.apache.commons.io.IOUtils;
import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Node;
import wsattacker.main.plugin.result.Result;
import wsattacker.main.plugin.result.ResultEntry;
import wsattacker.main.plugin.result.ResultLevel;
import wsattacker.plugin.dos.dosExtension.attackRunnables.LogRequestRunnable;
import wsattacker.plugin.dos.dosExtension.attackRunnables.UpdateNumberNetworktestProbesRunnable;
import wsattacker.plugin.dos.dosExtension.attackRunnables.UpdateNumberProbesRunnable;
import wsattacker.plugin.dos.dosExtension.attackRunnables.UpdateNumberRequestsRunnable;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;
import wsattacker.plugin.dos.dosExtension.util.UtilDos;

/**
 *
 * Sends SOAP requests and handles responses
 */
public class RequestSender {

    String responseString = "";
    AttackModel model;

    /*
     * Constructor - handle logging issue
     */
    public RequestSender(AttackModel model) {
	this.model = model;
    }
    
    /**
     * Send tampered request based on previously create postMethod
     *
     * @return
     */
    public String sendTamperedRequest() {
	RequestObject requestObject = model.getTamperedRequestObject();
	return this.sendRequestHttpClient(requestObject);
    }

    /**
     * Send untampered request based on previously create postMethod
     *
     * @return
     */
    public String sendUntamperedRequest() {
	RequestObject requestObject = model.getUntamperedRequestObject();
	return this.sendRequestHttpClient(requestObject);
    }

    /**
     * Send test probe request based on previously create postMethod
     *
     * @return
     */
    public String sendTestProbeRequest() {
	RequestObject requestObject = new RequestObject(this.model.getWsdlRequestOriginal());
	requestObject.setHttpHeaderMap(this.model.getOriginalRequestHeaderFields());
	return this.sendRequestHttpClient(requestObject);
    }
    
    /*
     * Disable excessive logging from HttpClient class
     */
    private static void disableExtensiveLogging() {
	java.util.logging.Logger.getLogger("org.apache.http.wire").setLevel(java.util.logging.Level.FINEST);
	java.util.logging.Logger.getLogger("org.apache.http.headers").setLevel(java.util.logging.Level.FINEST);
	System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
	System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
	System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "ERROR");
	System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http", "ERROR");
	System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.headers", "ERROR");
	System.setProperty("org.apache.commons.httpclient.HttpMethodBase", "ERROR");
    }

    /*
     * Prepare postMethod including header and payload
     * @param headerArray 
     */
    public PostMethod createHttpPostMethod(RequestObject requestObject) {
	
	Map<String, String> httpHeaderMap = requestObject.getHttpHeaderMap(); 
	String strUrl = requestObject.getEndpoint(); 
	String strXml = requestObject.getXmlMessage(); 
	
	RequestSender.disableExtensiveLogging();

	// Prepare HTTP post
	PostMethod post = new PostMethod(strUrl);

	// set Request content
	RequestEntity entity = null;
	try {
	    entity = new StringRequestEntity(strXml, "text/xml; charset=UTF-8", null);
	} catch (UnsupportedEncodingException ex) {
	    Logger.getLogger(RequestSender.class.getName()).log(Level.SEVERE, null, ex);
	}
	post.setRequestEntity(entity);

	// setRequestHeader (if already existant -> will be overwritten!)
	post.setRequestHeader("Content-type", "text/xml; UTF-8;");
	if(httpHeaderMap!=null){
	    for (Map.Entry<String, String> entry : httpHeaderMap.entrySet()) {
		post.setRequestHeader(entry.getKey(), entry.getValue());
	    }
	}
	// set for safety reason, just in case not set!
	post.setRequestHeader("Content-Length", String.valueOf(strXml.length()));

	return post;
    }


    /*
     * send Request using HttpClient
     */
    private String sendRequestHttpClient(RequestObject requestObject) {
	
	// get Post Request
	PostMethod post = this.createHttpPostMethod(requestObject);
	
	// Get HTTP client and execute request	
	try {
	    HttpClient httpclient = new HttpClient();
	    httpclient.getParams().setParameter("http.socket.timeout", new Integer(60000));
	    httpclient.getParams().setParameter("http.connection.timeout", new Integer(60000));	    
	    httpclient.getParams().setParameter("http.connection-manager.max-per-host", new Integer(60000));	
	    httpclient.getParams().setParameter("http.connection-manager.max-total", new Integer(3000));	
//>         params.setDefaultMaxConnectionsPerHost(3000);
//>         params.setMaxTotalConnections(3000);	    
	    
	    int result;
	    result = httpclient.executeMethod(post);
	    StringWriter writer = new StringWriter();
	    IOUtils.copy(post.getResponseBodyAsStream(), writer, "UTF-8");
	    responseString = writer.toString();
	    
	    //System.out.println("Response status code: " + result);
	    //System.out.println("Response body: " + responseString);
	} catch (IOException ex) {
	    //Logger.getLogger(RequestSender.class.getName()).log(Level.SEVERE, null, ex);
	    System.out.println("--RequestSender - IO Exception: " + ex.getMessage());
	} catch (Exception e) {
	    // Request timed out!?
	    System.out.println("--RequestSender - unexpected Exception: " + e.getMessage());
	} finally {
	    // Release current connection to the connection pool 
	    //post.releaseConnection();	    
	    
	    if(responseString==null)
		responseString="";	    
	    return responseString;
	}
    }

    /*
     * send Request using SOAPUi Api 
     */
    private String sendRequestSoapUi(WsdlRequest request) {
	try {
	    // do actual sending!
	    WsdlSubmit<WsdlRequest> submit = request.submit(new WsdlSubmitContext(request), false);
	    responseString = submit.getResponse().getContentAsString();

	} catch (Request.SubmitException e) {
	    // SubmitException
	    System.out.println("Request.SubmitException\n" + e.getMessage());
	} catch (Exception e) {
	    // Request timed out!?
	    System.out.println("Request timed out!\n" + e.getMessage());
	} finally {
	    if(responseString==null)
		responseString="";
	    return responseString;
	}
    }
}
