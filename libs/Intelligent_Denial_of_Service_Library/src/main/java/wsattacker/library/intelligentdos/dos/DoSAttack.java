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
package wsattacker.library.intelligentdos.dos;

import java.util.List;
import javax.xml.bind.annotation.XmlEnum;
import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.intelligentdos.common.DoSParam;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Christian Altmeier
 */
public interface DoSAttack
    extends Cloneable, Comparable<DoSAttack>
{

    @XmlEnum
    public static enum PayloadPosition
    {
        ELEMENT
        {
            private static final String PLACEHOLDER = "$$PAYLOADELEMENT$$";

            @Override
            public String createAndReplacePlaceholder( Document document, Element element )
            {
                createPlaceholder( document, element );
                return replace( document );
            }

            @Override
            public void createPlaceholder( Document document, Element element )
            {
                Element createElement = document.createElement( "PAYLOADELEMENT" );
                element.appendChild( createElement );
            }

            @Override
            public String replacePlaceholder( String xml, String tampered )
            {
                return StringUtils.replace( xml, PLACEHOLDER, tampered );
                // return xml.replace( PLACEHOLDER, tampered );
            }

            @Override
            public String placeholder()
            {
                return PLACEHOLDER;
            }
        },
        ATTRIBUTE
        {
            private static final String PLACEHOLDER = "$$PAYLOADATTR$$";

            @Override
            public String createAndReplacePlaceholder( Document document, Element element )
            {
                createPlaceholder( document, element );
                return replace( document );
            }

            @Override
            public void createPlaceholder( Document document, Element element )
            {
                element.setAttribute( "PAYLOAD", "PAYLOAD" );
            }

            @Override
            public String replacePlaceholder( String xml, String tampered )
            {
                return StringUtils.replace( xml, PLACEHOLDER, tampered );
                // return xml.replace( PLACEHOLDER, tampered );
            }

            @Override
            public String placeholder()
            {
                return PLACEHOLDER;
            }
        };

        public abstract String createAndReplacePlaceholder( Document document, Element element );

        public abstract void createPlaceholder( Document document, Element element );

        public abstract String replacePlaceholder( String xml, String tampered );

        public abstract String placeholder();

        public static String replace( Document document )
        {
            String domToString = DomUtilities.domToString( document );
            domToString = domToString.replace( "PAYLOAD=\"PAYLOAD\"", ATTRIBUTE.placeholder() );
            domToString = domToString.replace( "<PAYLOADELEMENT/>", ELEMENT.placeholder() );
            return domToString;
        }
    }

    String getName();

    PayloadPosition[] getPossiblePossitions();

    boolean hasFurtherParams();

    void nextParam();

    List<DoSParam<?>> getCurrentParams();

    String getTamperedRequest( String xml, PayloadPosition payloadPosition );

    String getUntamperedRequest( String xml, PayloadPosition payloadPosition );

    DoSAttack minimal();

    DoSAttack middle( DoSAttack doSAttack );

    void setUseNamespace( boolean useNamespace );

    DoSAttack clone()
        throws CloneNotSupportedException;

    void initialize();

}
