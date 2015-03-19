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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Map;

import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.DefaultHttpClient;

import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

public class Http4RequestSenderImpl
    implements RequestSender
{

    private static final Integer TIMEOUT = new Integer( 120000 );

    private final AttackModel model;

    private long receiveFirstByte;

    private long sendLastByte;

    private final boolean useProxy = Boolean.getBoolean( "useProxy" );

    public Http4RequestSenderImpl( AttackModel model )
    {
        this.model = model;
    }

    @Override
    public String sendTamperedRequest()
    {
        RequestObject requestObject = model.getTamperedRequestObject();
        return sendRequestHttpClient( requestObject );
    }

    @Override
    public String sendUntamperedRequest()
    {
        RequestObject requestObject = model.getUntamperedRequestObject();
        return sendRequestHttpClient( requestObject );
    }

    @Override
    public String sendTestProbeRequest()
    {
        RequestObject requestObject = new RequestObject( this.model.getWsdlRequestOriginal() );
        requestObject.setHttpHeaderMap( this.model.getOriginalRequestHeaderFields() );
        return this.sendRequestHttpClient( requestObject );
    }

    public String sendRequestHttpClient( RequestObject requestObject )
    {
        String strUrl = requestObject.getEndpoint();
        String strXml = requestObject.getXmlMessage();

        StringBuffer result = new StringBuffer();
        try
        {
            HttpClient client = new DefaultHttpClient();
            setParamsToClient( client );

            if ( useProxy )
            {
                HttpHost proxy = new HttpHost( "sbrproxy1.eur.ad.sag", 3103 );
                client.getParams().setParameter( ConnRoutePNames.DEFAULT_PROXY, proxy );
            }

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

            BufferedReader rd = new BufferedReader( new InputStreamReader( response.getEntity().getContent() ) );

            String line = "";
            while ( ( line = rd.readLine() ) != null )
            {
                result.append( line );
            }
        }
        catch ( NumberFormatException e )
        {

        }
        catch ( UnsupportedEncodingException e )
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        catch ( ClientProtocolException e )
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        catch ( IOException e )
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // if (!result.toString().contains("tema tis rolod muspi meroL")) {
        // System.out.println(result);
        // }

        return result.toString();
    }

    private void setParamsToClient( HttpClient client )
    {
        client.getParams().setParameter( "http.socket.timeout", TIMEOUT );
        client.getParams().setParameter( "http.connection.timeout", TIMEOUT );
        client.getParams().setParameter( "http.connection-manager.max-per-host", new Integer( 3000 ) );
        client.getParams().setParameter( "http.connection-manager.max-total", new Integer( 3000 ) );
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

    @Override
    public long getSendTime()
    {
        return sendLastByte;
    }

    @Override
    public long getReceiveTime()
    {
        return receiveFirstByte;
    }

    @Override
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

}
