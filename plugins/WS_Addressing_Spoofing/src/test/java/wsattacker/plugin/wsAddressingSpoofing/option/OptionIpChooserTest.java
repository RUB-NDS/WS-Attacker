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

import java.io.*;
import java.lang.reflect.Field;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.HttpStatus;
import static org.easymock.EasyMock.*;
import org.easymock.IAnswer;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.composition.plugin.option.AbstractOptionVarchar;
import wsattacker.main.plugin.option.OptionSimpleInteger;
import wsattacker.main.plugin.option.OptionSimpleVarchar;

/**
 * @author christian
 */
public class OptionIpChooserTest
{

    final private static String IP = "127.0.0.1";

    final private static String expectedResponseBody =
        String.format( "<html><head><title>Current IP Check</title></head><body>Current IP Address: %s</body></html>",
                       IP );

    public OptionIpChooserTest()
    {
    }

    @Test
    public void testDetectIP()
        throws Exception
    {
        AbstractOptionVarchar url = new OptionSimpleVarchar( "URL", "value" );
        AbstractOptionInteger port = new OptionSimpleInteger( "Port", 8080 );
        HttpClient mock = createMock( HttpClient.class );
        expect( mock.executeMethod( isA( HttpMethod.class ) ) ).andAnswer( new IAnswer<Integer>()
        {
            @Override
            public Integer answer()
                throws Throwable
            {
                HttpMethodBase httpMethod = (HttpMethodBase) (HttpMethod) getCurrentArguments()[0];
                Field responseStreamField = HttpMethodBase.class.getDeclaredField( "responseStream" );
                responseStreamField.setAccessible( true );
                responseStreamField.set( httpMethod,
                                         new ByteArrayInputStream( expectedResponseBody.getBytes( "UTF-8" ) ) );
                return HttpStatus.SC_OK;
            }
        } );
        expectLastCall().times( 2 );
        replay( mock );
        OptionIpChooser ipChooser = new OptionIpChooser( "IP Chooser", "Test for IP Chooser", url, port, mock );
        assertThat( ipChooser.detectIP(), is( IP ) );
        String expectedUrl = String.format( "http://%s:%d", IP, port.getValue() );
        assertThat( url.getValue(), is( expectedUrl ) );
        verify( mock );
    }
}
