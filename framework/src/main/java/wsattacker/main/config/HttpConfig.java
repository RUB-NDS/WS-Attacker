/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2010 Christian Mainka
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
package wsattacker.main.config;

import com.eviware.soapui.SoapUI;
import com.eviware.soapui.impl.wsdl.support.http.ProxyUtils;
import com.eviware.soapui.model.settings.Settings;
import com.eviware.soapui.settings.ProxySettings;
import org.jdesktop.beans.AbstractBean;

/**
 * @author dev
 */
public class HttpConfig
    extends AbstractBean
{

    public static final String PROP_PROXYHOST = "ProxyHost";

    public static final String PROP_PROXYPORT = "ProxyPort";

    public String getProxyHost()
    {
        return SoapUI.getSettings().getString( ProxySettings.HOST, "" );
    }

    public void setProxyHost( String httpProxyHost )
    {
        String oldHttpProxyHost = getProxyHost();
        final Settings settings = SoapUI.getSettings();
        if ( httpProxyHost == null || httpProxyHost.isEmpty() )
        {
            System.clearProperty( "http.proxyHost" );
            System.clearProperty( "https.proxyHost" );
            settings.setBoolean( ProxySettings.ENABLE_PROXY, false );
            ProxyUtils.setProxyEnabled( false );
        }
        else
        {
            System.setProperty( "http.proxyHost", httpProxyHost );
            System.setProperty( "https.proxyHost", httpProxyHost );
            settings.setString( ProxySettings.HOST, httpProxyHost );
            ProxyUtils.setProxyEnabled( true );
        }
        ProxyUtils.setGlobalProxy( settings );
        firePropertyChange( PROP_PROXYHOST, oldHttpProxyHost, httpProxyHost );
    }

    public String getProxyPort()
    {
        return SoapUI.getSettings().getString( ProxySettings.PORT, "" );
    }

    public void setProxyPort( String httpProxyPort )
    {
        String oldHttpProxyPort = getProxyPort();
        final Settings settings = SoapUI.getSettings();
        if ( httpProxyPort == null || httpProxyPort.isEmpty() )
        {
            System.clearProperty( "http.proxyPort" );
            System.clearProperty( "https.proxyPort" );
            settings.setBoolean( ProxySettings.ENABLE_PROXY, false );
            ProxyUtils.setProxyEnabled( false );
        }
        else
        {
            System.setProperty( "http.proxyPort", httpProxyPort );
            System.setProperty( "https.proxyPort", httpProxyPort );
            settings.setLong( ProxySettings.PORT, Long.parseLong( httpProxyPort ) );
            ProxyUtils.setProxyEnabled( true );
        }
        ProxyUtils.setGlobalProxy( settings );
        firePropertyChange( PROP_PROXYPORT, oldHttpProxyPort, httpProxyPort );
    }

}
