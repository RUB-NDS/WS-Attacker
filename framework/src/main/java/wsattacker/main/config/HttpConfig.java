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

    public static final String PROP_HTTPPROXYHOST = "httpProxyHost";

    public static final String PROP_HTTPPROXYPORT = "httpProxyPort";

    public static final String PROP_HTTPSPROXYHOST = "httpsProxyHost";

    public static final String PROP_HTTPSPROXYPORT = "httpsProxyPort";

    public String getHttpProxyHost()
    {
        return System.getProperty( "http.proxyHost" );
    }

    public void setHttpProxyHost( String httpProxyHost )
    {
        String oldHttpProxyHost = getHttpProxyHost();
        setProxyProperty("http.proxyHost", httpProxyHost );
        firePropertyChange( PROP_HTTPPROXYHOST, oldHttpProxyHost, httpProxyHost );
    }

    public String getHttpProxyPort()
    {
        return System.getProperty( "http.proxyPort" );
    }

    public void setHttpProxyPort( String httpProxyPort )
    {
        String oldHttpProxyPort = getHttpProxyPort();
        setProxyProperty( "http.proxyPort", httpProxyPort );
        firePropertyChange( PROP_HTTPPROXYPORT, oldHttpProxyPort, httpProxyPort );
    }

    public String getHttpsProxyHost()
    {
        return System.getProperty( "https.proxyHost" );
    }

    public void setHttpsProxyHost( String httpsProxyHost )
    {
        String oldHttpsProxyHost = getHttpsProxyHost();
        setProxyProperty( "https.proxyHost", httpsProxyHost );
        firePropertyChange( PROP_HTTPSPROXYHOST, oldHttpsProxyHost, httpsProxyHost );
    }

    public String getHttpsProxyPort()
    {
        return System.getProperty( "https.proxyPort" );
    }

    public void setHttpsProxyPort( String httpsProxyPort )
    {
        String oldHttpsProxyPort = getHttpsProxyPort();
        setProxyProperty( "https.proxyPort", httpsProxyPort );
        firePropertyChange( PROP_HTTPSPROXYPORT, oldHttpsProxyPort, httpsProxyPort );
    }

    private void setProxyProperty(String name, String value) {
        final Settings settings = SoapUI.getSettings();
        if (value == null || value.isEmpty()) {
            System.clearProperty(name);
            settings.setBoolean(ProxySettings.ENABLE_PROXY, false);
            ProxyUtils.setProxyEnabled(false);
        } else {
            System.setProperty( name, value );
            
            settings.setBoolean(ProxySettings.ENABLE_PROXY, true);
            switch(name) {
                case "http.proxyHost":
                case "https.proxyHost":
                    settings.setString(ProxySettings.HOST, value);
                    break;
                case "http.proxyPort":
                case "https.proxyPort":
                    settings.setLong(ProxySettings.PORT, Long.parseLong(value));
                    break;
                    
            }
            ProxyUtils.setProxyEnabled(true);
        }
        ProxyUtils.setGlobalProxy(settings);
    }

}
