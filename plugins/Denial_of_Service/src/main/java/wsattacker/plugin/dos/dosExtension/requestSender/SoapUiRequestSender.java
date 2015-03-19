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

import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

import com.eviware.soapui.impl.wsdl.WsdlOperation;
import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.WsdlSubmit;
import com.eviware.soapui.impl.wsdl.WsdlSubmitContext;
import com.eviware.soapui.model.iface.Request;

/**
 * @author chal
 */
public class SoapUiRequestSender
    implements RequestSender
{

    private final AttackModel model;

    private String responseString = "";

    private long start;

    private long end;

    public SoapUiRequestSender( AttackModel attackModel )
    {
        this.model = attackModel;
    }

    @Override
    public String sendTamperedRequest()
    {
        RequestObject requestObject = model.getTamperedRequestObject();

        String sendRequestSoapUi = createAndSend( requestObject );
        return sendRequestSoapUi;
    }

    @Override
    public String sendUntamperedRequest()
    {
        RequestObject requestObject = model.getUntamperedRequestObject();

        String sendRequestSoapUi = createAndSend( requestObject );
        return sendRequestSoapUi;
    }

    @Override
    public String sendTestProbeRequest()
    {
        RequestObject requestObject = new RequestObject( this.model.getWsdlRequestOriginal() );

        String sendRequestSoapUi = createAndSend( requestObject );
        return sendRequestSoapUi;
    }

    @Override
    public long getSendTime()
    {
        return start;
    }

    @Override
    public long getReceiveTime()
    {
        return end;
    }

    @Override
    public long getDuration()
    {
        return end - start;
    }

    private String createAndSend( RequestObject requestObject )
    {
        WsdlOperation operation = model.getWsdlRequestOriginal().getOperation();
        WsdlRequest wsdlRequest = operation.addNewRequest( "Basic Request" );
        wsdlRequest.setRequestContent( requestObject.getXmlMessage() );

        String sendRequestSoapUi = this.sendRequestSoapUi( wsdlRequest );
        return sendRequestSoapUi;
    }

    /*
     * send Request using SOAPUi Api
     */
    private String sendRequestSoapUi( WsdlRequest request )
    {
        try
        {
            start = System.nanoTime();

            // do actual sending!
            WsdlSubmit<WsdlRequest> submit = request.submit( new WsdlSubmitContext( request ), false );
            responseString = submit.getResponse().getContentAsString();
            end = System.nanoTime();
        }
        catch ( Request.SubmitException e )
        {
            // SubmitException
            System.out.println( "Request.SubmitException\n" + e.getMessage() );
        }
        catch ( Exception e )
        {
            // Request timed out!?
            System.out.println( "Request timed out!\n" + e.getMessage() );
        }
        finally
        {
            if ( responseString == null )
            {
                responseString = "";
            }
        }

        return responseString;
    }

}
