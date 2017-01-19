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
package wsattacker.http.transport;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.impl.wsdl.submit.transports.http.WsdlResponse;
import com.eviware.soapui.impl.wsdl.support.http.HttpClientSupport;
import com.eviware.soapui.support.types.StringToStringsMap;
import java.io.*;
import java.util.*;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class SoapHttpClient
{

    /**
     * if the connection is closed, the client tries to send the soap message again, max MAX_RETRY_NUMBER times
     */
    private static int MAX_RETRY_NUMBER = 3;

    /**
     * holds the current instance of the object
     */
    private static SoapHttpClient currentInstance = null;

    /**
     * http client
     */
    private HttpClient client;

    /**
     * http post
     */
    private HttpPost post;

    private static Logger LOG = Logger.getLogger( SoapHttpClient.class );

    SoapHttpClient( WsdlRequest request )
    {
        this( request.getEndpoint() );
        setSoapUiHeaders( request );
    }

    SoapHttpClient( String destinationUrl )
    {
        this.client = TlsWrapperClient.wrapClient( new DefaultHttpClient() );
        this.post = new HttpPost( destinationUrl );
        setConfigProxy();
    }

    private void setConfigProxy()
    {
        final String protocol = post.getURI().getScheme();
        if ( "http".equals( protocol ) || "https".equals( protocol ) )
        {
            final String httpProxyHost = System.getProperty( protocol + ".proxyHost" );
            final String proxyPortAsString = System.getProperty( protocol + ".proxyPort" );
            if ( httpProxyHost != null && !httpProxyHost.isEmpty() && proxyPortAsString != null
                && !proxyPortAsString.isEmpty() )
            {
                try
                {
                    final int httpProxyPort = Integer.parseInt( proxyPortAsString );
                    if ( httpProxyHost != null && !httpProxyHost.isEmpty() )
                    {
                        final HttpHost proxy = new HttpHost( httpProxyHost, httpProxyPort, protocol );
                        client.getParams().setParameter( ConnRoutePNames.DEFAULT_PROXY, proxy );
                    }
                }
                catch ( NumberFormatException e )
                {
                    Logger.getLogger( SoapHttpClient.class ).warn( String.format( "Could not set Proxy for %s with value with value '%s'",
                                                                                  protocol, proxyPortAsString ), e );
                }
            }
        }
    }

    public static boolean isContentLengthHeader( String name )
    {
        return "Content-Length".equals( name );
    }

    private void setSoapUiHeaders( WsdlRequest request )
    {
        final WsdlResponse response = request.getResponse();
        if ( response != null )
        {
            final StringToStringsMap requestBasicHeaders = response.getRequestHeaders();
            setHeaders( requestBasicHeaders );

        }
        final StringToStringsMap additionalHeaders = request.getRequestHeaders();
        setHeaders( additionalHeaders );
    }

    private void setHeaders( final StringToStringsMap headers )
    {
        for ( Map.Entry<String, List<String>> header : headers.entrySet() )
        {
            String name = header.getKey();
            if ( isContentLengthHeader( name ) )
            {
                LOG.debug( "HTTP-Header 'Content-Length' will be recalculated." );
                continue;
            }
            for ( String value : header.getValue() )
            {
                post.setHeader( name, value );
            }
        }
    }

    /**
     * Get the current soap http client initialized with the URL and wsdl request
     * 
     * @return
     */
    public static SoapHttpClient getSoapHttpClient()
    {
        return currentInstance;
    }

    /**
     * Sends the SOAP message to the initialized endpoint destination
     * 
     * @param soap
     * @return
     * @throws IOException
     */
    public SoapResponse sendSoap( String soap )
        throws IOException
    {

        final StringEntity httpBody = new StringEntity( soap );
        post.setEntity( httpBody );

        int maxTries = MAX_RETRY_NUMBER;
        HttpResponse httpResponse = null;
        while ( httpResponse == null )
        {
            try
            {
                httpResponse = client.execute( post );
            }
            catch ( IOException ex )
            {
                if ( maxTries == 0 )
                {
                    throw ex;
                }
                else
                {
                    maxTries--;
                    LOG.warn( ex.getLocalizedMessage() );
                    LOG.warn( "Trying to send the message once more" );
                    LOG.debug( ex );
                }
            }
        }

        SoapResponse soapResponse = new SoapResponse();

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( httpResponse.getStatusLine() );
        }
        soapResponse.setStatusLine( httpResponse.getStatusLine().toString() );
        for ( Header h : httpResponse.getAllHeaders() )
        {
            final String name = h.getName();
            final String value = h.getValue();
            if ( LOG.isDebugEnabled() )
            {
                final String headerDebug = name + ": " + value;
                LOG.debug( headerDebug );
            }
            HttpHeader newHeader = new HttpHeader( name, value );
            soapResponse.getHeaders().add( newHeader );
        }
        LOG.debug( "waiting for response: " );

        final HttpEntity entity = httpResponse.getEntity();
        final String charset = EntityUtils.getContentCharSet( entity );
        final String responseString = EntityUtils.toString( entity, charset );
        soapResponse.setBody( responseString );
        return soapResponse;
    }

    /**
     * Shuts down the connection manager and releases all the allocated resources
     */
    public void shutDownConnectionManager()
    {
        client.getConnectionManager().shutdown();
    }

}
