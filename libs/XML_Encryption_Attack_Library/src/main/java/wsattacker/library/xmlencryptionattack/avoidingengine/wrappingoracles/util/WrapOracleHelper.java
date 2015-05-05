/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Dennis Kupser
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

package wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.util;

import java.util.List;
import org.w3c.dom.Element;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Dennis
 */
public class WrapOracleHelper
{

    public static void handleEncKeyInEncData( EncryptedDataElement encPay )
    {
        ElementAttackProperties encPayProp = null;
        encPayProp = encPay.getAttackProperties();
        if ( null != encPay.getKeyInfoElement() )
        {
            if ( null != encPay.getKeyInfoElement().getEncryptedKeyElement() )
            {
                EncryptedKeyElement encKeyInEncData = null;
                ElementAttackProperties encKeyInEncDataProp = null;
                List<Element> encKeys = null;
                encKeyInEncData = encPay.getKeyInfoElement().getEncryptedKeyElement();
                encKeyInEncDataProp = encKeyInEncData.getAttackProperties();

                encKeys =
                    DomUtilities.findChildren( encPayProp.getAttackPayloadElement(), "EncryptedKey", URI_NS_ENC, true );

                if ( 1 == encKeys.size() )
                {
                    encKeyInEncDataProp.setAttackPayloadElement( encKeys.get( 0 ) );
                }
                else
                    throw new IllegalArgumentException( "Error: this should never happen -> "
                        + "payload element has not one encrypted key element inside" );
            }
        }
    }

}
