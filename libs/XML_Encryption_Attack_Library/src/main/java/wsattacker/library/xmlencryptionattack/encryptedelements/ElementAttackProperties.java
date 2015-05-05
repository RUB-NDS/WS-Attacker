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

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import org.w3c.dom.Element;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.NO_CURR_WRAP_IDX;
import wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.WrappingAttackMode;
import static wsattacker.library.xmlencryptionattack.util.XMLEncryptionConstants.WrappingAttackMode.NO_WRAP;

/**
 * @author Dennis
 */
public final class ElementAttackProperties
{
    private Element m_SignedPart = null;

    private Element m_WrappingPayloadElemnt = null;

    private int m_CurrWrappingPayloadIdx = NO_CURR_WRAP_IDX;

    private WrappingAttackMode m_CurrWrappingMode = NO_WRAP;

    private Element m_AttackPayloadElemnt = null;

    private boolean m_IsAdditionalWrap = false;

    private int m_SignMode = -1;

    private final transient PropertyChangeSupport m_PropertyChangeSupport = new java.beans.PropertyChangeSupport( this );

    public static final String PROP_SIGNEDELEMENT = "signedElement";

    public static final String PROP_REFERRINGELEMENT = "referringElement";

    public static final String PROP_WRAPPINGELMENT = "wrappingElement";

    public static final String PROP_ATTACKELEMENT = "attackElement";

    /**
     * @return
     */
    public Element getWrappingPayloadElement()
    {
        return m_WrappingPayloadElemnt;
    }

    /**
     * @param wrappingPayloadEl
     */
    public void setWrappingPayloadElement( Element wrappingPayloadEl )
    {
        Element oldPayloadElement = this.m_WrappingPayloadElemnt;
        this.m_WrappingPayloadElemnt = wrappingPayloadEl;
        m_PropertyChangeSupport.firePropertyChange( PROP_WRAPPINGELMENT, oldPayloadElement, m_WrappingPayloadElemnt );
        this.m_WrappingPayloadElemnt = wrappingPayloadEl;
        setCurrWrappingPayloadIdx( NO_CURR_WRAP_IDX );
        setCurrWrappingMode( NO_WRAP );
    }

    /**
     * @return
     */
    public Element getAttackPayloadElement()
    {
        return m_AttackPayloadElemnt;
    }

    /**
     * @param wrappingPayloadEl
     */
    public void setAttackPayloadElement( Element attackPayloadEl )
    {
        Element attackElement = this.m_AttackPayloadElemnt;
        this.m_AttackPayloadElemnt = attackPayloadEl;
        m_PropertyChangeSupport.firePropertyChange( PROP_ATTACKELEMENT, attackElement, m_AttackPayloadElemnt );
        this.m_AttackPayloadElemnt = attackPayloadEl;
        this.m_AttackPayloadElemnt = attackPayloadEl;
    }

    /**
     * @return
     */
    public int getSignMode()
    {
        return m_SignMode;
    }

    /**
     * @param signMode
     */
    public void setSignMode( int signMode )
    {
        this.m_SignMode = signMode;
    }

    /**
     * @param referencedElement
     */
    public void setSignedPart( Element referencedElement )
    {
        Element oldSignedElement = this.m_SignedPart;
        this.m_SignedPart = referencedElement;
        m_PropertyChangeSupport.firePropertyChange( PROP_SIGNEDELEMENT, oldSignedElement, m_SignedPart );
        this.m_SignedPart = referencedElement;
    }

    /**
     * @return
     */
    public Element getSignedPart()
    {
        return this.m_SignedPart;
    }

    public boolean isSigned()
    {
        if ( null == m_SignedPart )
            return false;
        else
            return true;
    }

    public boolean isAdditionalWrap()
    {
        return m_IsAdditionalWrap;
    }

    public void setIsAdditionalWrap( boolean isAdditionalWrap )
    {
        this.m_IsAdditionalWrap = isAdditionalWrap;
    }

    /**
     * Add PropertyChangeListener.
     * 
     * @param listener
     */
    public void addPropertyChangeListener( final PropertyChangeListener listener )
    {
        m_PropertyChangeSupport.addPropertyChangeListener( listener );
    }

    /**
     * Add PropertyChangeListener.
     * 
     * @param propertyName
     * @param listener
     */
    public void addPropertyChangeListener( final String propertyName, final PropertyChangeListener listener )
    {
        m_PropertyChangeSupport.addPropertyChangeListener( propertyName, listener );
    }

    /**
     * Remove PropertyChangeListener.
     * 
     * @param listener
     */
    public void removePropertyChangeListener( final PropertyChangeListener listener )
    {
        m_PropertyChangeSupport.removePropertyChangeListener( listener );
    }

    /**
     * Remove PropertyChangeListener.
     * 
     * @param propertyName
     * @param listener
     */
    public void removePropertyChangeListener( final String propertyName, final PropertyChangeListener listener )
    {
        m_PropertyChangeSupport.removePropertyChangeListener( propertyName, listener );
    }

    public int getCurrWrappingPayloadIdx()
    {
        return m_CurrWrappingPayloadIdx;
    }

    public void setCurrWrappingPayloadIdx( int m_CurrWrappingPayloadIdx )
    {
        this.m_CurrWrappingPayloadIdx = m_CurrWrappingPayloadIdx;
    }

    public WrappingAttackMode getCurrWrappingMode()
    {
        return m_CurrWrappingMode;
    }

    public void setCurrWrappingMode( WrappingAttackMode currWrappingMode )
    {
        this.m_CurrWrappingMode = currWrappingMode;
    }

}
