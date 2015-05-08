/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Dennis Kupser
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

package wsattacker.plugin.xmlencryptionattack;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import java.io.IOException;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import wsattacker.http.transport.SoapHttpClient;
import wsattacker.http.transport.SoapHttpClientFactory;
import wsattacker.http.transport.SoapResponse;
import wsattacker.library.xmlencryptionattack.util.ServerSendCommandIF;
import wsattacker.main.plugin.result.Result;
import wsattacker.main.plugin.result.ResultEntry;
import wsattacker.main.plugin.result.ResultLevel;

/**
 * @author Dennis
 */
public class WebServiceSendCommand
    implements ServerSendCommandIF
{
    private static final Logger LOG = Logger.getLogger( WebServiceSendCommand.class );

    private SoapHttpClient m_SoapHttpClient;

    public WebServiceSendCommand( WsdlRequest oracleRequest )
    {
        this.m_SoapHttpClient = SoapHttpClientFactory.createSoapHttpClient( oracleRequest );
    }

    @Override
    public String send( String message )
    {
        SoapResponse response = null;
        try
        {
            // log( "Request:\n" + message );
            response = m_SoapHttpClient.sendSoap( message );
            // log( "Response:\n" + response.getBody() );
        }
        catch ( IOException ex )
        {
            LOG.log( Level.ERROR, ex );

        }

        return response.getBody();
    }

    @Override
    public void cleanCmd()
    {
        if ( m_SoapHttpClient != null )
        {
            m_SoapHttpClient.shutDownConnectionManager();
            m_SoapHttpClient = null;
        }
    }

    public void log( String logMessage )
    {
        Result.getGlobalResult().add( new ResultEntry( ResultLevel.Trace, "XMLEncryptionAttack", logMessage ) );
    }

}
