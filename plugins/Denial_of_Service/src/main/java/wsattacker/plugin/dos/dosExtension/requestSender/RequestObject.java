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

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import com.eviware.soapui.support.types.StringToStringsMap;

/**
 * RequestObjects are used to send requests via various constructors can be used to build the RequestObject
 */
public class RequestObject
{

    private String xmlMessage = "";

    private String endpoint;

    private Map<String, String> httpHeaderMap;

    private byte[] compressedXML = null;

    public RequestObject()
    {
    }

    public RequestObject( String xmlMessage, String endpoint, Map<String, String> httpHeaderMap )
    {
        this.xmlMessage = xmlMessage;
        this.endpoint = endpoint;
        this.httpHeaderMap = httpHeaderMap;
        // this.setHeaderContentLength();
    }

    public RequestObject( byte[] compressedXML, String endpoint, Map<String, String> httpHeaderMap )
    {
        this.setCompressedXML( compressedXML );
        this.endpoint = endpoint;
        this.httpHeaderMap = httpHeaderMap;
        // this.setHeaderContentLength();
    }

    public RequestObject( WsdlRequest wsdlRequest )
    {
        this.xmlMessage = wsdlRequest.getRequestContent();
        this.endpoint = wsdlRequest.getEndpoint();
        this.createHttpHeaderMap( wsdlRequest );
        // this.setHeaderContentLength();
    }

    public void createHttpHeaderMap( WsdlRequest wsdlRequest )
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

    /*
     * return Header as multiline string
     */
    public String getHeaderString( String linebreak )
    {
        Iterator<String> iterator = httpHeaderMap.keySet().iterator();
        StringBuilder sb = new StringBuilder( "" );
        while ( iterator.hasNext() )
        {
            String key = iterator.next();
            String value = httpHeaderMap.get( key );
            sb.append( key ).append( " " ).append( value ).append( linebreak );
        }
        return sb.toString();
    }

    // /*
    // * Set correct content length Should be called whenever content of message
    // * is set or changed OR when Header is overwritten
    // */
    // public void setHeaderContentLength() {
    // httpHeaderMap
    // .put("Content-Length", String.valueOf(xmlMessage.length()));
    // }

    public String getXmlMessage()
    {
        return xmlMessage;
    }

    public void setXmlMessage( String xmlMessage )
    {
        this.xmlMessage = xmlMessage;
        // this.setHeaderContentLength();
    }

    public byte[] getCompressedXML()
    {
        return compressedXML;
    }

    public void setCompressedXML( byte[] compressedXML2 )
    {
        this.compressedXML = compressedXML2;
    }

    public String getEndpoint()
    {
        return endpoint;
    }

    public void setEndpoint( String endpoint )
    {
        this.endpoint = endpoint;
    }

    public Map<String, String> getHttpHeaderMap()
    {
        return httpHeaderMap;
    }

    public void setHttpHeaderMap( Map<String, String> httpHeaderMap )
    {
        this.httpHeaderMap = httpHeaderMap;
        // this.setHeaderContentLength();
    }

    public int getXmlMessageLength()
    {
        if ( compressedXML != null )
        {
            return compressedXML.length;
        }
        else
        {
            return this.xmlMessage.length();

        }
    }
}
