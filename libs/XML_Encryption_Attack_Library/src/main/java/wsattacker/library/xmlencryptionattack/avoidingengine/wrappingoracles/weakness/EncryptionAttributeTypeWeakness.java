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

package wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.ENC_TYPE_CONTENT;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.ENC_TYPE_ELEMENT;

public class EncryptionAttributeTypeWeakness
    extends AbstractWeaknessComposite
{
    private final static Logger LOG = Logger.getLogger( EncryptionAttributeTypeWeakness.class );

    public EncryptionAttributeTypeWeakness( AbstractEncryptionElement encPay )
    {
        this.m_EncPay = encPay;
        if ( null != m_EncPay.getType() )
            this.m_PossibleWeaks = 2;
        else
            this.m_PossibleWeaks = 1;
    }

    @Override
    public int getPossibleNumWeaks()
    {
        return m_PossibleWeaks;
    }

    @Override
    public void abuseWeakness( int index, Element encKey, Element encPay )
    {
        index %= m_PossibleWeaks;

        switch ( index )
        {
        // 0) hold Type
            case 0:
                LOG.info( "Hold Encryption Type of element " + encPay.getLocalName() );
                break;
            // 1) ToggleType
            case 1:
                toggleEncryptionType( encPay );
                break;

            default:

                String error = "Index out of range: '" + index + "'";
                LOG.warn( error );

        }
    }

    private void toggleEncryptionType( Element encPay )
    {
        String encType = encPay.getAttributeNode( "Type" ).getValue();

        if ( encType.equals( ENC_TYPE_ELEMENT ) )
        {
            encPay.getAttributeNode( "Type" ).setValue( ENC_TYPE_CONTENT );
        }
        else
        {
            encPay.getAttributeNode( "Type" ).setValue( ENC_TYPE_ELEMENT );
        }

        LOG.info( "Encryption Type of element " + encPay.getLocalName() + " changed to "
            + encPay.getAttributeNode( "Type" ).getValue() );

    }

}
