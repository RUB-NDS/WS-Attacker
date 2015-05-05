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
package wsattacker.library.xmlencryptionattack.encryptedelements;

import java.util.List;
import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.KeyInfoElement;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.URI_NS_ENC;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * This class represents the base class of the encrypted elements. Here we initialize the properties of the encrypted
 * objects.
 * 
 * @author Dennis Kupser
 */
public abstract class AbstractEncryptionElement
{

    /**
     * The CipherDataChild can reference (CipherReference) the encrypted content or the encrypted content is inside of a
     * CipherValue element.
     */
    protected CipherDataChildIF m_CipherDataChild = null;

    protected KeyInfoElement m_KeyInfoElement = null;

    /**
     * The encrypted element can be an EncryptedData or an EncryptedKey element
     */
    protected String m_EncryptionMethod = null;

    protected String m_IdValue = null;

    protected String m_MimeType = null;

    protected String m_Type = null;

    protected Element m_EncryptedElement = null;

    protected Element m_CipherDataElement = null;

    protected final ElementAttackProperties m_AttackProperties = new ElementAttackProperties();

    protected final static Logger LOG = Logger.getLogger( AbstractEncryptionElement.class );

    public ElementAttackProperties getAttackProperties()
    {
        return m_AttackProperties;
    }

    /**
     * @return
     */
    public CipherDataChildIF getCipherDataChild()
    {
        return m_CipherDataChild;
    }

    /**
     * @return
     */
    public KeyInfoElement getKeyInfoElement()
    {
        return m_KeyInfoElement;
    }

    /**
     * @return
     */
    public Element getEncryptedElement()
    {
        return m_EncryptedElement;
    }

    /**
     * @return
     */
    public String getEncryptionMethod()
    {
        return m_EncryptionMethod;
    }

    /**
     * @return
     */
    public String getIdValue()
    {
        return m_IdValue;
    }

    /**
     * @return
     */
    public String getMimeType()
    {
        return m_MimeType;
    }

    /**
     * @return
     */
    public String getType()
    {
        return m_Type;
    }

    /**
     * @param encDataElement
     */
    protected void initEncryptionElement( Element encDataElement )
    {
        if ( null != encDataElement )
        {
            this.m_EncryptedElement = encDataElement;
            List<Element> cipherData = null;
            cipherData = DomUtilities.findChildren( encDataElement, "CipherData", URI_NS_ENC );
            List<Element> keyInfoElements = DomUtilities.findChildren( encDataElement, "KeyInfo", null, true );

            if ( 0 < keyInfoElements.size() )
            {
                m_KeyInfoElement = new KeyInfoElement( keyInfoElements.get( 0 ) );
            }

            if ( 1 == cipherData.size() )
            {
                List<Element> cipherDataChild = null;
                cipherDataChild = DomUtilities.findChildren( cipherData.get( 0 ), "CipherValue", URI_NS_ENC );
                this.m_CipherDataElement = cipherData.get( 0 );
                if ( 1 == cipherDataChild.size() )
                {
                    this.m_CipherDataChild = new CipherValueElement( cipherDataChild.get( 0 ) );
                }
                else if ( cipherDataChild.isEmpty() )
                {
                    cipherDataChild = DomUtilities.findChildren( cipherData.get( 0 ), "CipherReference", URI_NS_ENC );

                    if ( 1 == cipherDataChild.size() )
                    {
                        this.m_CipherDataChild = new CipherReferenceElement( cipherDataChild.get( 0 ) );
                    }
                    else if ( 1 <= cipherDataChild.size() )
                        throw new IllegalArgumentException( "parameter '"
                            + "cipherDataChild'->CipherReference size must not be bigger than one" );
                    else
                        throw new IllegalArgumentException( "no 'cipherDataChild' detected" );
                }
                else
                    throw new IllegalArgumentException( "parameter "
                        + "'cipherDataChild'->CipherValue size must not be bigger than one" );

                this.m_EncryptionMethod =
                    DomUtilities.findChildren( this.m_EncryptedElement, "EncryptionMethod", null ).get( 0 ).getAttribute( "Algorithm" );
                this.m_IdValue = this.m_EncryptedElement.getAttribute( "Id" );
                this.m_MimeType = this.m_EncryptedElement.getAttribute( "MimeType" );
                this.m_Type = this.m_EncryptedElement.getAttribute( "Type" );
            }
            else
                throw new IllegalArgumentException( "parameter 'cipherData' size must not be empty or bigger than one" );

        }
        else
            throw new IllegalArgumentException( "parameter 'encDataElement' must not be null" );

    }

    public Element getCipherDataElement()
    {
        return m_CipherDataElement;
    }

    public boolean isValid( String value )
    {
        boolean isValid = true;
        if ( value.length() >= 3 )
        {
            try
            {
                DomUtilities.stringToDom( value );
            }
            catch ( Exception e )
            {
                LOG.error( "Payload.isValid() Error: " + e.getLocalizedMessage() );
                isValid = false;
            }
        }
        return isValid;
    }

}