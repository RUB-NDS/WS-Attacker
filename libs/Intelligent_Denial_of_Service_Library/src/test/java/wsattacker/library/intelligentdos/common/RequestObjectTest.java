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
package wsattacker.library.intelligentdos.common;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.support.types.StringToStringsMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import org.mockito.Mockito;
import static org.mockito.Mockito.when;

/**
 * @author Christian Altmeier
 */
public class RequestObjectTest
{

    @Test( expected = IllegalArgumentException.class )
    public void nullConstructor()
    {
        new RequestObject( null );
    }

    @Test
    public void wsdlRequestConstructor()
    {
        String endpoint = "http://localhost:8080/dummy";
        String content = "<soap></soap>";
        StringToStringsMap map = new StringToStringsMap();
        map.put( "lorem", Lists.newArrayList( "ipsum" ) );

        WsdlRequest w = Mockito.mock( WsdlRequest.class );
        when( w.getEndpoint() ).thenReturn( endpoint );
        when( w.getRequestContent() ).thenReturn( content );
        when( w.getRequestHeaders() ).thenReturn( map );

        RequestObject requestObject = new RequestObject( w );

        assertThat( requestObject.getEndpoint(), is( endpoint ) );
        assertThat( requestObject.getRequestContent(), is( content ) );
        Map<String, String> httpHeaderMap = requestObject.getHttpHeaderMap();
        Set<Entry<String, String>> entrySet = httpHeaderMap.entrySet();
        assertThat( httpHeaderMap.size(), is( 1 ) );
        Entry<String, String> first = entrySet.iterator().next();
        assertThat( first.getKey(), is( "lorem" ) );
        assertThat( first.getValue(), is( "ipsum" ) );
    }

    @Test
    public void paramConstructor()
    {
        String endpoint = "http://localhost:8080/dummy";
        String content = "<soap></soap>";
        Map<String, String> map = Maps.newHashMap();
        map.put( "lorem", "ipsum" );
        RequestObject requestObject = new RequestObject( content, endpoint, map );

        assertThat( requestObject.getEndpoint(), is( endpoint ) );
        assertThat( requestObject.getRequestContent(), is( content ) );
        assertEquals( requestObject.getHttpHeaderMap(), map );

        Map<String, String> httpHeaderMap = requestObject.getHttpHeaderMap();
        assertThat( httpHeaderMap.size(), is( 1 ) );

        Set<Entry<String, String>> entrySet = httpHeaderMap.entrySet();
        Entry<String, String> first = entrySet.iterator().next();
        assertThat( first.getKey(), is( "lorem" ) );
        assertThat( first.getValue(), is( "ipsum" ) );
    }

}
