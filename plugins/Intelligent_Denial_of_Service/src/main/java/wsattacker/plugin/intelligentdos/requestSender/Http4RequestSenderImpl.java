/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.plugin.intelligentdos.requestSender;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;

import wsattacker.library.intelligentdos.common.RequestObject;

public class Http4RequestSenderImpl
{
    public static final Integer TIMEOUT = Integer.valueOf( 5000 );

    private static int httpConnectionTimeout;

    private long receiveFirstByte;

    private long sendLastByte;

    public static void setHttpConnectionTimeout( int httpConnectionTimeout )
    {
        Http4RequestSenderImpl.httpConnectionTimeout = httpConnectionTimeout;
    }

    public String sendRequestHttpClient( RequestObject requestObject )
    {
        String strUrl = requestObject.getEndpoint();
        String strXml = requestObject.getRequestContent();

        StringBuilder result = new StringBuilder();
        BufferedReader rd = null;
        try
        {
            URL url = new URL( strUrl );
            String protocol = url.getProtocol();

            HttpClient client;
            if ( protocol.equalsIgnoreCase( "https" ) )
            {
                SSLSocketFactory sf = get();
                Scheme httpsScheme = new Scheme( "https", url.getPort(), sf );
                SchemeRegistry schemeRegistry = new SchemeRegistry();
                schemeRegistry.register( httpsScheme );

                // apache HttpClient version >4.2 should use
                // BasicClientConnectionManager
                ClientConnectionManager cm = new SingleClientConnManager( schemeRegistry );

                client = new DefaultHttpClient( cm );
            }
            else
            {
                client = new DefaultHttpClient();
            }

            setParamsToClient( client );

            HttpPost post = new HttpPost( strUrl );
            setHeader( requestObject, post );

            ByteArrayEntity entity = new ByteArrayEntity( strXml.getBytes( "UTF-8" ) )
            {
                @Override
                public void writeTo( OutputStream outstream )
                    throws IOException
                {
                    super.writeTo( outstream );
                    sendLastByte = System.nanoTime();
                }
            };

            post.setEntity( entity );
            HttpResponse response = client.execute( post );
            receiveFirstByte = System.nanoTime();

            rd =
                new BufferedReader( new InputStreamReader( response.getEntity().getContent(), Charset.defaultCharset() ) );

            String line = "";
            while ( ( line = rd.readLine() ) != null )
            {
                result.append( line );
            }
        }
        catch ( IOException e )
        {
            return e.getMessage();
        }
        catch ( RuntimeException e )
        {
            return e.getMessage();
        }
        finally
        {
            if ( rd != null )
            {
                try
                {
                    rd.close();
                }
                catch ( IOException e )
                {
                    e.printStackTrace();
                }
            }
        }

        return result.toString();
    }

    private SSLSocketFactory get()
    {

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] { new TrustAllManager() };

        // Install the all-trusting trust manager
        try
        {
            SSLContext sc = SSLContext.getInstance( "TLS" );
            sc.init( null, trustAllCerts, new SecureRandom() );
            HttpsURLConnection.setDefaultSSLSocketFactory( sc.getSocketFactory() );
            return new SSLSocketFactory( sc, SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER );
        }
        catch ( RuntimeException e )
        {
            ;
        }
        catch ( Exception e )
        {
            ;
        }

        return null;

    }

    private void setParamsToClient( HttpClient client )
    {
        int timeout = TIMEOUT;
        if ( httpConnectionTimeout > 0 )
        {
            timeout = httpConnectionTimeout;
        }
        HttpParams params = client.getParams();
        params.setParameter( "http.socket.timeout", timeout );
        params.setParameter( "http.connection.timeout", timeout );
        params.setParameter( "http.connection-manager.max-per-host", 3000 );
        params.setParameter( "http.connection-manager.max-total", 3000 );

        HttpConnectionParams.setConnectionTimeout( params, timeout );
        HttpConnectionParams.setSoTimeout( params, timeout );
    }

    private void setHeader( RequestObject requestObject, HttpPost post )
    {
        Map<String, String> httpHeaderMap = requestObject.getHttpHeaderMap();
        post.setHeader( "Content-type", "text/xml; UTF-8;" );
        post.setHeader( "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0" );
        // HTTP 1.1.
        post.setHeader( "Cache-Control", "no-cache, no-store, must-revalidate" );
        post.setHeader( "Pragma", "no-cache" ); // HTTP 1.0
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
    }

    public long getSendTime()
    {
        return sendLastByte;
    }

    public long getReceiveTime()
    {
        return receiveFirstByte;
    }

    public long getDuration()
    {
        return receiveFirstByte - sendLastByte;
    }

    class MyByteArrayEntity
        extends ByteArrayEntity
    {

        public MyByteArrayEntity( byte[] b )
        {
            super( b );
        }

        @Override
        public void writeTo( OutputStream outstream )
            throws IOException
        {
            super.writeTo( outstream );
            sendLastByte = System.nanoTime();
        }

    }

    private static class TrustAllManager
        implements X509TrustManager
    {
        @Override
        public X509Certificate[] getAcceptedIssuers()
        {
            return new X509Certificate[0];
        }

        @Override
        public void checkClientTrusted( X509Certificate[] certs, String authType )
        {
        }

        @Override
        public void checkServerTrusted( X509Certificate[] certs, String authType )
        {
        }
    }
}
