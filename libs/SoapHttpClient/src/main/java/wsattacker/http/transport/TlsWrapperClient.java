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

import java.io.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.DefaultHttpClient;

public class TlsWrapperClient
{

    public static HttpClient wrapClient( HttpClient base )
    {
        try
        {
            SSLContext ctx = SSLContext.getInstance( "TLS" );
            X509TrustManager tm = new X509TrustManager()
            {
                public void checkClientTrusted( X509Certificate[] xcs, String string )
                    throws CertificateException
                {
                }

                public void checkServerTrusted( X509Certificate[] xcs, String string )
                    throws CertificateException
                {
                }

                public X509Certificate[] getAcceptedIssuers()
                {
                    return null;
                }
            };
            X509HostnameVerifier verifier = new X509HostnameVerifier()
            {
                @Override
                public void verify( String string, X509Certificate xc )
                    throws SSLException
                {
                }

                @Override
                public void verify( String string, String[] strings, String[] strings1 )
                    throws SSLException
                {
                }

                @Override
                public boolean verify( String string, SSLSession ssls )
                {
                    return true;
                }

                @Override
                public void verify( String string, SSLSocket ssls )
                    throws IOException
                {
                }
            };
            ctx.init( null, new TrustManager[] { tm }, null );
            SSLSocketFactory ssf = new SSLSocketFactory( ctx );
            ssf.setHostnameVerifier( verifier );
            ClientConnectionManager ccm = base.getConnectionManager();
            SchemeRegistry sr = ccm.getSchemeRegistry();
            sr.register( new Scheme( "https", ssf, 443 ) );
            return new DefaultHttpClient( ccm, base.getParams() );
        }
        catch ( NoSuchAlgorithmException ex )
        {
            return null;
        }
        catch ( KeyManagementException ex )
        {
            return null;
        }
    }
}
