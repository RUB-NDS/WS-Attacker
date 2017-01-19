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

import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.AbstractHttpEntity;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;
import wsattacker.main.Preferences;
import wsattacker.main.config.HttpConfig;

import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

/**
 * Sends SOAP requests and handles responses
 */
public class RequestSenderImpl
    implements RequestSender
{

    private static final Integer TIMEOUT = new Integer( 60000 );

    private long beforeSend;

    private long afterReceive;

    private final AttackModel model;

    private String responseString = "";

    /*
     * Constructor - handle logging issue
     */
    public RequestSenderImpl( AttackModel model )
    {
        this.model = model;
    }

    /**
     * Send tampered request based on previously create postMethod
     * 
     * @return
     */
    @Override
    public String sendTamperedRequest()
    {
        RequestObject requestObject = model.getTamperedRequestObject();
        return this.sendRequestHttpClient( requestObject );
    }

    /**
     * Send untampered request based on previously create postMethod
     * 
     * @return
     */
    @Override
    public String sendUntamperedRequest()
    {
        RequestObject requestObject = model.getUntamperedRequestObject();
        return this.sendRequestHttpClient( requestObject );
    }

    /**
     * Send test probe request based on previously create postMethod
     * 
     * @return
     */
    @Override
    public String sendTestProbeRequest()
    {
        RequestObject requestObject = new RequestObject( this.model.getWsdlRequestOriginal() );
        requestObject.setHttpHeaderMap( this.model.getOriginalRequestHeaderFields() );
        return this.sendRequestHttpClient( requestObject );
    }

    /*
     * Disable excessive logging from HttpClient class
     */
    private static void disableExtensiveLogging()
    {
        java.util.logging.Logger.getLogger( "org.apache.http.wire" ).setLevel( java.util.logging.Level.FINEST );
        java.util.logging.Logger.getLogger( "org.apache.http.headers" ).setLevel( java.util.logging.Level.FINEST );
        System.setProperty( "org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog" );
        System.setProperty( "org.apache.commons.logging.simplelog.showdatetime", "true" );
        System.setProperty( "org.apache.commons.logging.simplelog.log.httpclient.wire", "ERROR" );
        System.setProperty( "org.apache.commons.logging.simplelog.log.org.apache.http", "ERROR" );
        System.setProperty( "org.apache.commons.logging.simplelog.log.org.apache.http.headers", "ERROR" );
        System.setProperty( "org.apache.commons.httpclient.HttpMethodBase", "ERROR" );
    }

    /*
     * Prepare postMethod including header and payload
     * @param headerArray
     */
    private HttpPost createHttpPostMethod( RequestObject requestObject )
    {

        Map<String, String> httpHeaderMap = requestObject.getHttpHeaderMap();
        String strUrl = requestObject.getEndpoint();
        String strXml = requestObject.getXmlMessage();
        byte[] compressedXml = requestObject.getCompressedXML();

        RequestSenderImpl.disableExtensiveLogging();

        HttpPost post = null;
        try
        {
            // Prepare HTTP post
            post = new HttpPost( strUrl );
            AbstractHttpEntity entity = null;
            // set Request content
            if ( compressedXml != null )
            {
                entity = new ByteArrayEntity( compressedXml );
            }
            else
            {
                try
                {
                    entity = new StringEntity( strXml, "text/xml; charset=UTF-8", null );
                }
                catch ( UnsupportedEncodingException ex )
                {
                    Logger.getLogger( RequestSenderImpl.class.getName() ).log( Level.SEVERE, null, ex );
                }
            }

            // setRequestHeader (if already existent -> will be overwritten!)
            post.setHeader( "Content-type", "text/xml; UTF-8;" );
            if ( httpHeaderMap != null )
            {
                for ( Map.Entry<String, String> entry : httpHeaderMap.entrySet() )
                {
                    // Content-Length is automatically set by HTTPClient
                    if ( !entry.getKey().equalsIgnoreCase( "Content-Length" ) )
                    {
                        post.setHeader( entry.getKey(), entry.getValue() );
                    }
                }
            }
            post.setEntity( entity );

            // set for safety reason, just in case not set!
            // post.setHeader("Content-Length",
            // String.valueOf(strXml.length()));
        }
        catch ( Exception e )
        {
            // TODO [CHAL 2014-01-03] Not really clear why we have to catch an
            // exception here, but without the catch we got an error by eclipse
            // that an exception will not been caught
            Logger.getLogger( RequestSenderImpl.class.getName() ).log( Level.SEVERE, null, e );
        }

        return post;
    }

    /*
     * send Request using HttpClient
     */
    private String sendRequestHttpClient( RequestObject requestObject )
    {

        // get Post Request
        HttpPost post = this.createHttpPostMethod( requestObject );

        // set afterReceive to default value to handle missing responses
        afterReceive = 0;

        // Get HTTP client and execute request
        try
        {
            URL url = new URL( requestObject.getEndpoint() );
            String protocol = url.getProtocol();

            HttpClient httpClient;
            if ( protocol.equalsIgnoreCase( "https" ) )
            {
                SSLContext ctx = SSLContext.getInstance( "TLS" );
                X509TrustManager tm = new X509TrustManager()
                {
                    @Override
                    public void checkClientTrusted( X509Certificate[] xcs, String string )
                        throws CertificateException
                    {
                    }

                    @Override
                    public void checkServerTrusted( X509Certificate[] xcs, String string )
                        throws CertificateException
                    {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers()
                    {
                        return null;
                    }
                };
                ctx.init( null, new TrustManager[] { tm }, null );

                SSLSocketFactory sf = new SSLSocketFactory( ctx, SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER );
                Scheme httpsScheme = new Scheme( "https", url.getPort(), sf );
                SchemeRegistry schemeRegistry = new SchemeRegistry();
                schemeRegistry.register( httpsScheme );

                // apache HttpClient version >4.2 should use
                // BasicClientConnectionManager
                ClientConnectionManager cm = new SingleClientConnManager( schemeRegistry );

                httpClient = new DefaultHttpClient( cm );
            }
            else
            {
                httpClient = new DefaultHttpClient();
            }

            httpClient.getParams().setParameter( "http.socket.timeout", TIMEOUT );
            httpClient.getParams().setParameter( "http.connection.timeout", TIMEOUT );
            httpClient.getParams().setParameter( "http.connection-manager.max-per-host", TIMEOUT );
            httpClient.getParams().setParameter( "http.connection-manager.max-total", new Integer( 3000 ) );
            // > params.setDefaultMaxConnectionsPerHost(3000);
            // > params.setMaxTotalConnections(3000);

            final HttpConfig httpConfig = Preferences.getInstance().getHttpConfig();
            if ( !httpConfig.getProxyHost().isEmpty() && !httpConfig.getProxyPort().isEmpty() )
            {
                HttpHost proxy =
                    new HttpHost( httpConfig.getProxyHost(), Integer.parseInt( httpConfig.getProxyPort() ) );
                httpClient.getParams().setParameter( ConnRoutePNames.DEFAULT_PROXY, proxy );
            }

            beforeSend = System.nanoTime();

            HttpResponse response = httpClient.execute( post );
            StringWriter writer = new StringWriter();
            IOUtils.copy( response.getEntity().getContent(), writer, "UTF-8" );
            responseString = writer.toString();

            afterReceive = System.nanoTime();
            // System.out.println("Response status code: " + result);
            // System.out.println("Response body: " + responseString);
        }
        catch ( IOException ex )
        {
            // Logger.getLogger(RequestSender.class.getName()).log(Level.SEVERE,
            // null, ex);
            System.out.println( "--RequestSender - IO Exception: " + ex.getMessage() );

            // ex.printStackTrace();
        }
        catch ( Exception e )
        {
            // Request timed out!?
            System.out.println( "--RequestSender - unexpected Exception: " + e.getMessage() );
        }
        finally
        {
            // Release current connection to the connection pool
            // post.releaseConnection();

            if ( responseString == null )
            {
                responseString = "";
            }

            // Set afterReceive to beforeSend if afterReceive is 0 so that there
            // is no huge negative response time when the web service doesn't answer
            if ( afterReceive == 0 )
            {
                afterReceive = beforeSend;
            }
        }

        return responseString;
    }

    @Override
    public long getSendTime()
    {
        return beforeSend;
    }

    @Override
    public long getReceiveTime()
    {
        return afterReceive;
    }

    @Override
    public long getDuration()
    {
        return afterReceive - beforeSend;
    }
}
