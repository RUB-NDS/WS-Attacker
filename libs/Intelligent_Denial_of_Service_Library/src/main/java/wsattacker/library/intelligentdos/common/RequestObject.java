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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RequestObject
{

    private final String requestContent;

    private Map<String, String> httpHeaderMap;

    private final String endpoint;

    public RequestObject( WsdlRequest wsdlRequest )
    {
        if ( wsdlRequest == null )
        {
            throw new IllegalArgumentException( "wsdlRequest cannot be null!" );
        }

        this.requestContent = wsdlRequest.getRequestContent();
        this.endpoint = wsdlRequest.getEndpoint();
        this.createHttpHeaderMap( wsdlRequest );
    }

    public RequestObject( String requestContent, String endpoint, Map<String, String> httpHeaderMap )
    {
        this.requestContent = requestContent;
        this.endpoint = endpoint;
        this.httpHeaderMap = httpHeaderMap;
    }

    public String getRequestContent()
    {
        return requestContent;
    }

    public String getEndpoint()
    {
        return endpoint;
    }

    public Map<String, String> getHttpHeaderMap()
    {
        return httpHeaderMap;
    }

    private void createHttpHeaderMap( WsdlRequest wsdlRequest )
    {
        httpHeaderMap = new HashMap<String, String>();
        StringToStringsMap originalHeaders = wsdlRequest.getRequestHeaders();
        for ( Map.Entry<String, List<String>> entry : originalHeaders.entrySet() )
        {
            for ( String value : entry.getValue() )
            {
                httpHeaderMap.put( entry.getKey(), value );
            }
        }
    }

}
