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
package wsattacker.plugin.wsAddressingSpoofing.option;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.log4j.Logger;

import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.composition.plugin.option.AbstractOptionVarchar;
import wsattacker.main.plugin.option.OptionSimpleChoice;

public class OptionIpChooser
    extends OptionSimpleChoice
{

    private static final String URL = "http://checkip.dyndns.org";

    public static final String AUTO = String.format( "Detect your IP via %s", URL );

    public static final String MANUAL = "Edit settings below as you like";

    private static final String REGEX = "[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}";

    private static final Pattern PATTERN = Pattern.compile( REGEX );

    final private static Logger LOG = Logger.getLogger( OptionIpChooser.class );

    final private static long serialVersionUID = 2L;

    final private AbstractOptionVarchar url;

    final private AbstractOptionInteger port;

    private HttpClient httpClient;

    public OptionIpChooser( String name, String description, AbstractOptionVarchar url, AbstractOptionInteger port )
    {
        this( name, description, url, port, new HttpClient() );
    }

    protected OptionIpChooser( String name, String description, AbstractOptionVarchar url, AbstractOptionInteger port,
                               final HttpClient httpClient )
    {
        super( name, description );
        this.httpClient = httpClient;
        List<String> choices = new ArrayList<String>();
        choices.add( MANUAL );
        choices.add( AUTO );
        setChoices( choices );
        this.url = url;
        this.port = port;
        setSelectedAsString( AUTO );
    }

    @Override
    public void setSelectedAsString( String selected )
    {
        super.setSelectedAsString( selected );
        if ( AUTO.equals( selected ) )
        {
            updateUrl();
        }
    }

    public String detectIP()
    {
        String ip = null;

        // Create a method instance.
        GetMethod method = new GetMethod( URL );

        // Provide custom retry handler is necessary
        // method.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, new
        // DefaultHttpMethodRetryHandler(3, false));
        String html;
        try
        {
            // Execute the method.
            int statusCode = httpClient.executeMethod( method );

            if ( statusCode != HttpStatus.SC_OK )
            {
                LOG.error( "Could not fetch website to detect IP" );
                return null;
            }

            // Read the response body.
            byte[] responseBody = method.getResponseBody();

            // Deal with the response.
            // Use caution: ensure correct character encoding and is not binary
            // data
            html = new String( responseBody );

        }
        catch ( HttpException e )
        {
            LOG.error( "Could not fetch website to detect IP" );
            return null;
        }
        catch ( IOException e )
        {
            LOG.error( "Could not fetch website to detect IP" );
            return null;
        }
        finally
        {
            // Release the connection.
            method.releaseConnection();
        }
        Matcher m = PATTERN.matcher( html );

        // first match is used
        m.find();
        ip = html.substring( m.start(), m.end() );

        return ip;

    }

    private void updateUrl()
    {
        String ip = detectIP();
        if ( ip == null )
        {
            url.setValue( "Could not detect your IP" );
        }
        else
        {
            url.setValue( "http://" + ip + ":" + port.getValue() );
        }
        setSelectedAsString( MANUAL );
    }
}
