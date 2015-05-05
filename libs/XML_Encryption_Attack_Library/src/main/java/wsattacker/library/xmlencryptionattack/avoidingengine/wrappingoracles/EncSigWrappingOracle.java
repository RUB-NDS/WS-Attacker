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

import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.library.signatureWrapping.xpath.wrapping.WrappingOracle;
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

public class EncSigWrappingOracle
    extends WrappingOracle
    implements WrappingOracleIF
{
    private final AbstractEncryptionElement m_EncPay;

    private final ElementAttackProperties m_EncPayAttackProp;

    private final int m_MaxSigWrappPossibilites;

    private int m_MaxPossibilites;

    public final static Logger LOG = Logger.getLogger( EncSigWrappingOracle.class );

    private final List<AbstractEncryptionWeakness> m_EncryptionWeakness = new ArrayList<AbstractEncryptionWeakness>();

    public EncSigWrappingOracle( AbstractEncryptionElement encPay, DetectionReport detRep, SchemaAnalyzer schemaAnalyser )
        throws InvalidPayloadException, InvalidWeaknessException
    {
        super( detRep.getRawFile(),
               ( (SignatureInfo) detRep.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER ) ).getUsedPayloads(),
               schemaAnalyser );
        SignatureInfo sigInfo = (SignatureInfo) detRep.getDetectionInfo( DetectFilterEnum.SIGNATUREFILTER );
        this.m_EncPay = encPay;
        this.m_MaxSigWrappPossibilites = super.maxPossibilities();
        this.m_MaxPossibilites = m_MaxSigWrappPossibilites;

        if ( null == m_EncPay )
            LOG.error( "Error: No encryption element detected in EncSigWrappingOracle" );

        this.m_EncPayAttackProp = m_EncPay.getAttackProperties();

        if ( null == m_EncPayAttackProp )
            LOG.error( "Error: No Attack Properties set for Payload in EncSigWrappingOracle" );

        if ( !sigInfo.isSignature() )
            LOG.error( "No signature detected -> no wrapping-attack needed" );

        initWeaknessesOfEncKey();
        initWeaknessesOfEncDataOnly();
    }

    private void initWeaknessesOfEncDataOnly()
        throws InvalidWeaknessException, IllegalArgumentException
    {
        int signMode = 0;
        // seperate encDatas without encKeys
        if ( m_EncPay instanceof EncryptedDataElement )
        {
            if ( m_EncPayAttackProp.isSigned() )
            {
                signMode = m_EncPayAttackProp.getSignMode();
                if ( 0 < ( Node.DOCUMENT_POSITION_CONTAINED_BY & signMode ) && !m_EncPay.getIdValue().equals( "" ) )
                    setEncryptionIdWeakness( m_EncPay, null );
                else
                    LOG.info( "No encryption Id weaknesses: Signature Wrapping Oracle handling" );
            }
        }
    }

    private void initWeaknessesOfEncKey()
        throws IllegalArgumentException, InvalidWeaknessException
    {
        int signMode = 0;
        // handle only AttributeWeakness if encElement is signed directly + encKeyRefWeakness
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
                if ( attackProps.isSigned() )
                {
                    signMode = attackProps.getSignMode();

                    if ( 0 < ( Node.DOCUMENT_POSITION_CONTAINED_BY & signMode ) )
                        setEncryptionIdWeakness( encDataRef, (EncryptedKeyElement) m_EncPay );
                    else if ( 0 == signMode ) // put only new id from XSW-Lib to EncKey
                        setEncryptedKeyRefWeakness( encDataRef, (EncryptedKeyElement) m_EncPay );
                }
            }
            else if ( encRefs.get( idxEncDataPay ) instanceof KeyReferenceElement )
            {
                throw new IllegalArgumentException( "keyreference not supported yet!" );
            }
            // encKEy signed??
            if ( m_EncPayAttackProp.isSigned() )
            {
                signMode = m_EncPayAttackProp.getSignMode();
                if ( 0 < ( Node.DOCUMENT_POSITION_CONTAINED_BY & signMode ) )
                    setEncryptionIdWeakness( m_EncPay, (EncryptedKeyElement) m_EncPay );
            }
        }
    }

    @Override
    public Document getPossibility( int index )
        throws InvalidWeaknessException
    {
        WeaknessLog.clean();
        LOG.info( "Creating Wrapping Possibility " + index + " of (" + m_MaxPossibilites + "-1)" );
        int weakPropIdx = 0;
        Element payElement = null;
        Element encKeyPay = null;

        // 3 signature cases:
        // 1.: Enc-Element as child (parent + encdata child are sigend)
        // 2.: Enc-Element as parent (parent sigend)
        // 3.: Parts of the enc-element are sigend (determine the sigend encData) (!!!not relevant yet!!!)
        Document attackDocument = super.getPossibility( index % m_MaxSigWrappPossibilites );
        // Document attackDocEnc = DomUtilities.createNewDomFromNode(attackDocument.getDocumentElement());
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
                if ( attackProps.isSigned() )
                {
                    int possibility =
                        ( index / m_MaxSigWrappPossibilites )
                            % m_EncryptionWeakness.get( weakPropIdx ).getPossibleNumWeaks();
                    payElement =
                        DomUtilities.findCorrespondingElement( attackDocument, attackProps.getWrappingPayloadElement() );
                    attackProps.setAttackPayloadElement( payElement );
                    if ( m_EncPayAttackProp.isSigned() )
                    {
                        encKeyPay =
                            DomUtilities.findCorrespondingElement( attackDocument,
                                                                   (Element) m_EncPayAttackProp.getWrappingPayloadElement() );
                    }
                    else
                    {
                        encKeyPay =
                            DomUtilities.findCorrespondingElement( attackDocument, m_EncPay.getEncryptedElement() );
                    }
                    m_EncPayAttackProp.setAttackPayloadElement( encKeyPay );

                    m_EncryptionWeakness.get( weakPropIdx ).abuseWeakness( possibility, encKeyPay, payElement );
                    weakPropIdx++;
                }
            }
            else if ( encRefs.get( idxEncDataPay ) instanceof KeyReferenceElement )
            {
                throw new IllegalArgumentException( "keyreference not supported yet!" );
            }
            // encKey signed??
            if ( m_EncPayAttackProp.isSigned() )
            {
                if ( 0 < ( Node.DOCUMENT_POSITION_CONTAINED_BY & m_EncPayAttackProp.getSignMode() ) )
                {
                    int possibility = index % m_EncryptionWeakness.get( weakPropIdx ).getPossibleNumWeaks();
                    index /= m_EncryptionWeakness.get( weakPropIdx ).getPossibleNumWeaks();

                    if ( null == encKeyPay )
                    {
                        encKeyPay =
                            DomUtilities.findCorrespondingElement( attackDocument,
                                                                   (Element) m_EncPayAttackProp.getWrappingPayloadElement() );
                        m_EncPayAttackProp.setAttackPayloadElement( encKeyPay );
                    }
                    m_EncryptionWeakness.get( weakPropIdx ).abuseWeakness( possibility, null, encKeyPay );
                    weakPropIdx++;
                }
            }
        }

        handleEncDataOnly( index, weakPropIdx, attackDocument );

        return attackDocument;
    }

    private void handleEncDataOnly( int index, int weakPropIdx, Document attackDocument )
        throws IllegalArgumentException
    {
        Element payElement = null;
        // handle encDatasOnly (without encKeys)
        if ( m_EncPay instanceof EncryptedDataElement )
        {
            if ( m_EncPayAttackProp.isSigned() )
            {
                if ( 0 < ( Node.DOCUMENT_POSITION_CONTAINED_BY & m_EncPayAttackProp.getSignMode() ) )
                {
                    payElement =
                        DomUtilities.findCorrespondingElement( attackDocument,
                                                               (Element) m_EncPayAttackProp.getWrappingPayloadElement() );
                    if ( null == payElement )
                        throw new IllegalArgumentException( "Err: payload is null" );

                    m_EncPayAttackProp.setAttackPayloadElement( payElement );
                    WrapOracleHelper.handleEncKeyInEncData( (EncryptedDataElement) m_EncPay );

                    if ( !m_EncryptionWeakness.isEmpty() )
                    {
                        int possibility =
                            ( index / m_MaxSigWrappPossibilites )
                                % m_EncryptionWeakness.get( weakPropIdx ).getPossibleNumWeaks();
                        m_EncryptionWeakness.get( weakPropIdx ).abuseWeakness( possibility, null, payElement );
                        weakPropIdx++;
                    }

                }
            }
        }
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
    public int maxPossibilities()
    {
        return m_MaxPossibilites;
    }

    private void setEncryptionIdWeakness( AbstractEncryptionElement encPay, EncryptedKeyElement encKey )
        throws InvalidWeaknessException
    {
        AbstractEncryptionWeakness encAttrWeak =
            FactoryWeakness.generateWeakness( WeaknessType.ATTR_ID_WEAKNESS, encPay, encKey );
        setMaxPossibilites( encAttrWeak.getPossibleNumWeaks(), encPay.getEncryptedElement() );
        m_EncryptionWeakness.add( encAttrWeak );
    }

    private void setEncryptedKeyRefWeakness( AbstractEncryptionElement encPay, EncryptedKeyElement encKey )
        throws InvalidWeaknessException
    {
        AbstractEncryptionWeakness encAttrWeak =
            FactoryWeakness.generateWeakness( WeaknessType.ENCKEY_REF_WEAKNESS, encPay, encKey );
        setMaxPossibilites( encAttrWeak.getPossibleNumWeaks(), encPay.getEncryptedElement() );
        m_EncryptionWeakness.add( encAttrWeak );
    }

    @Override
    public void addAdditionalEncryptionWeakness( AbstractEncryptionWeakness addWeak )
    {
        throw new UnsupportedOperationException( "Not supported yet." ); // To change body of generated methods, choose
                                                                         // Tools | Templates.
    }
}
