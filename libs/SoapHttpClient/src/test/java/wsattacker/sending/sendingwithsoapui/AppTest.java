/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2014 Christian Mainka
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
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sending.sendingwithsoapui;

import com.eviware.soapui.impl.wsdl.WsdlProject;
import com.eviware.soapui.impl.wsdl.WsdlProjectFactory;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.WsdlSubmit;
import com.eviware.soapui.impl.wsdl.WsdlSubmitContext;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import wsattacker.http.transport.SoapHttpClient;
import wsattacker.http.transport.SoapHttpClientFactory;
import wsattacker.http.transport.SoapResponse;

/**
 * @author dev
 */
public class AppTest
{

    private static final Logger LOG = Logger.getLogger( AppTest.class );

    private static WsdlRequest request;

    public AppTest()
    {
    }

    @BeforeClass
    public static void setUpClass()
        throws Exception
    {

        // soapUI Projekt
        WsdlProjectFactory projectFacory = new WsdlProjectFactory();
        WsdlProject project = projectFacory.createNew();

        // wsdl die geladen werden soll
        // String wsdlURL = "http://cryptochallenge.nds.rub.de:8080/axis2/services/CreditCardPayment?wsdl";
        // String wsdlURL = "http://localhost:52080/axis2/services/Version?wsdl";

        // importieren der WSDL
        // WsdlInterface iface = WsdlInterfaceFactory.importWsdl( project, wsdlURL, false )[0];

        // nimm erste verfuegbare operation
        // WsdlOperation operation = (WsdlOperation) iface.getOperationList().get( 0 );
        // alternativ beim namen
        // operation = iface.getOperationByName("GetPrim");

        // fuege neuen request hinzu, name ist egal und wird nur als "identifier" benutzt
        // request = operation.addNewRequest( "One" );
        // request = operation.addNewRequest( "getVersion" );

        // fuege default request content hinzu, optionale elemente=true
        // request.setRequestContent( operation.createRequest( true ) );
    }

    /**
     * Test of main method, of class App.
     */
    @Test
    @Ignore
    public void sendWithSoapUI()
        throws Exception
    {
        WsdlSubmitContext wsdlSubmitContext = new WsdlSubmitContext( request );
        // absenden des requets
        // for(int i=0; i<20; ++i) {
        WsdlSubmit<WsdlRequest> submit = (WsdlSubmit<WsdlRequest>) request.submit( wsdlSubmitContext, false );
        // Response response = submit.getResponse();
        // System.out.println("REQUEST:\n" + response.getRequestHeaders() + "\n" + response.getRequestContent());
        // System.out.println("RESPONSE:\n" + response.getResponseHeaders() + "\n" + response.getContentAsString());
        // }

    }

    @Test
    @Ignore
    public void sendDirect()
        throws Exception
    {
        // final String uri = request.getEndpoint();
        final String body = request.getRequestContent();
        final SoapHttpClient h = SoapHttpClientFactory.createSoapHttpClient( request );
        final SoapResponse response = h.sendSoap( body );
    }

    @Test
    @Ignore
    public void sendDirectMany()
        throws Exception
    {
        int max = 200;
        final String body = request.getRequestContent();
        final SoapHttpClient h = SoapHttpClientFactory.createSoapHttpClient( request );
        long start = System.nanoTime();
        for ( int i = 0; i < max; i++ )
        {
            h.sendSoap( body );
        }
        h.shutDownConnectionManager();
    }

    @Test
    @Ignore
    public void send80000()
        throws Exception
    {
        final String body = request.getRequestContent();
        final SoapHttpClient h = SoapHttpClientFactory.createSoapHttpClient( request );
        SoapResponse response = h.sendSoap( body );
        for ( int i = 0; 80000 > i; i++ )
        {
            h.sendSoap( body );
        }
    }
}
