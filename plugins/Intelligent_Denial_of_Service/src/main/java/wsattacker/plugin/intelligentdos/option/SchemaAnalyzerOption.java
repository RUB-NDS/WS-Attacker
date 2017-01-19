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
package wsattacker.plugin.intelligentdos.option;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.schemaanalyzer.AnyElementProperties;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.main.composition.plugin.option.AbstractOptionString;
import wsattacker.main.testsuite.CurrentRequest;
import wsattacker.main.testsuite.TestSuite;

/**
 * @author Christian Altmeier
 */
public class SchemaAnalyzerOption
    extends AbstractOptionString
    implements PropertyChangeListener
{

    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;

    private static final String DEFAULT_SOAP_MESSAGE =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><Envelope><Header/><Body></Body></Envelope>";

    private transient final SchemaAnalyzer schemaAnalyzer;

    public SchemaAnalyzerOption( String name, String value, SchemaAnalyzer schemaAnalyzer )
    {
        super( name, value );
        this.schemaAnalyzer = schemaAnalyzer;

        TestSuite.getInstance().getCurrentRequest().addPropertyChangeListener( this );
    }

    @Override
    public boolean isValid( String value )
    {
        return StringUtils.isNotBlank( value );
    }

    private String create( String newContent )
    {
        String domToString = newContent;
        try
        {
            Document toAnalyze = DomUtilities.stringToDom( newContent );
            Set<AnyElementProperties> expansionPoints = findExpansionPoints( toAnalyze );

            Document stringToDom = null;
            for ( AnyElementProperties element : expansionPoints )
            {
                stringToDom = DomUtilities.stringToDom( domToString );
                Element correspondingElement =
                    DomUtilities.findCorrespondingElement( stringToDom, element.getDocumentElement() );

                PayloadPosition.ELEMENT.createPlaceholder( stringToDom, correspondingElement );
                PayloadPosition.ATTRIBUTE.createPlaceholder( stringToDom, correspondingElement );

                domToString = DomUtilities.domToString( stringToDom );
            }

            if ( stringToDom != null )
            {
                domToString = PayloadPosition.replace( stringToDom );
            }

        }
        catch ( SAXException ex )
        {
            Logger.getLogger( SchemaAnalyzerOption.class.getName() ).log( Level.SEVERE, null, ex );
        }
        return domToString;
    }

    private Set<AnyElementProperties> findExpansionPoints( Document toAnalyze )
    {
        Element documentElement = toAnalyze.getDocumentElement();

        return schemaAnalyzer.findExpansionPoint( documentElement );
    }

    @Override
    public void propertyChange( PropertyChangeEvent evt )
    {
        final String propName = evt.getPropertyName();
        String create = DEFAULT_SOAP_MESSAGE;

        if ( CurrentRequest.PROP_WSDLREQUEST.equals( propName ) )
        {

            if ( evt.getNewValue() != null )
            {
                WsdlRequest newRequest = (WsdlRequest) evt.getNewValue();
                create = create( newRequest.getRequestContent() );
            }

        }
        else if ( CurrentRequest.PROP_WSDLREQUESTCONTENT.equals( propName ) )
        {
            if ( evt.getNewValue() != null )
            {
                String newContent = (String) evt.getNewValue();
                create = create( newContent );
            }
        }
        else if ( CurrentRequest.PROP_WSDLRESPONSE.equals( propName )
            || CurrentRequest.PROP_WSDLRESPONSECONTENT.equals( propName ) )
        {
            // nothing to do
            return;
        }

        setValue( create );

    }

}
