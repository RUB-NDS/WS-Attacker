/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Mainka
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
package wsattacker.library.signatureWrapping.xpath.wrapping;

import java.util.*;
import javax.xml.namespace.QName;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.option.PayloadElement;
import wsattacker.library.signatureWrapping.option.SignedElement;
import wsattacker.library.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.util.signature.ReferenceElement;
import wsattacker.library.signatureWrapping.util.signature.XPathElement;
import wsattacker.library.signatureWrapping.xpath.analysis.XPathAnalyser;
import wsattacker.library.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import static wsattacker.library.xmlutilities.namespace.NamespaceConstants.URI_NS_DS;

/**
 * High Level Algorithm for creating XSW Messages. The WrappingOracle takes an signed input message, a SignatureManager
 * and the List of Payload to create it.
 */
public class WrappingOracle
{

    private final SchemaAnalyzer schemaAnalyser;

    private final Document originalDocument;

    private List<Payload> payloadList;

    private final List<QName> filterList;

    private final List<XPathAnalyser> analyserList;

    int maxPossibilites;

    // statistics
    private int countSignedElements;

    private int countElementsReferedByID;

    private int countElementsReferedByXPath;

    private int countElementsReferedByFastXPath;

    private int countElementsReferedByPrefixfreeTransformedFastXPath;

    public final static Logger LOG = Logger.getLogger( WrappingOracle.class );

    /**
     * Constructor class.
     * 
     * @param originalDocument
     * @param payloads
     * @param schemaAnalyser
     */
    public WrappingOracle( Document originalDocument, List<Payload> payloads, SchemaAnalyzer schemaAnalyser )
    {
        this.originalDocument = originalDocument;
        this.payloadList = payloads;
        this.schemaAnalyser = schemaAnalyser;
        this.filterList = new ArrayList<QName>();
        this.analyserList = new ArrayList<XPathAnalyser>();
        init();
    }

    /**
     * @return The maximum number of possible XSW messages.
     */
    public int maxPossibilities()
    {
        return maxPossibilites;
    }

    /**
     * Returns the i-th possible XSW message. The original document is not changed.
     * 
     * @param index
     * @return XSW message
     * @throws InvalidWeaknessException
     */
    public Document getPossibility( int index )
        throws InvalidWeaknessException
    {
        WeaknessLog.clean();
        Document attackDocument = DomUtilities.createNewDomFromNode( originalDocument.getDocumentElement() );
        LOG.info( "Creating Wrapping Possibility " + index + " of (" + maxPossibilites + "-1)" );

        for ( int i = 0; i < payloadList.size(); ++i )
        {

            Payload payload = payloadList.get( i );
            XPathAnalyser xpa = analyserList.get( i );

            int possibility = index % xpa.getMaxPossibilites();
            index /= xpa.getMaxPossibilites();

            Element signedElement = DomUtilities.findCorrespondingElement( attackDocument, payload.getSignedElement() );
            Element payloadElement;
            try
            {
                payloadElement = (Element) attackDocument.importNode( payload.getPayloadElement(), true );
            }
            catch ( Exception e )
            {
                LOG.warn( "Could not get Payload Element for " + signedElement.getNodeName() + " / Skipping." );
                continue;
            }

            // We must be carefull: The refferringElement commonly points to the
            // original Document
            // but not to the newly created attackerDocument.
            // // Thus we must use the findCorrespondingElement method.
            Element refferingElement =
                DomUtilities.findCorrespondingElement( signedElement.getOwnerDocument(),
                                                       payload.getReferringElement().getElementNode() );
            PayloadElement pay = new PayloadElement( payloadElement, refferingElement );
            pay.setUseThisPayloadElement( !payload.isWrapOnly() );
            SignedElement sig = new SignedElement( signedElement, refferingElement );
            xpa.abuseWeakness( possibility, sig, pay );
        }

        return attackDocument;
    }

    /**
     * Private init methods. Analyzes the referenced elements and estimates the number of possible XSW messages.
     */
    private void init()
    {
        /*********************************************************************/
        // 12042014dk: possibility to set filterlist before calling init method
        /*********************************************************************/
        if ( null != schemaAnalyser.getFilterList() )
        {
            if ( schemaAnalyser.getFilterList().isEmpty() )
            {
                filterList.add( new QName( URI_NS_DS, "SignedInfo" ) );
                filterList.add( new QName( URI_NS_DS, "SignatureValue" ) );
                schemaAnalyser.setFilterList( filterList );
            }
        }
        /*********************************************************************/

        maxPossibilites = 0;
        List<Payload> usedPayloads = new ArrayList<Payload>();
        // Filter out unused payloads
        for ( Payload payload : payloadList )
        {
            // statistics
            ++countSignedElements;
            if ( payload.getReferringElement() instanceof ReferenceElement )
            {
                ++countElementsReferedByID;
            }
            else if ( payload.getReferringElement() instanceof XPathElement )
            {
                ++countElementsReferedByXPath;
            }

            if ( payload.hasPayload() || payload.isTimestamp() )
            {
                Element payloadElement;
                try
                {
                    payloadElement = payload.getPayloadElement();
                }
                catch ( InvalidPayloadException e )
                {
                    LOG.warn( "Could not get Payload Element for " + payload.getSignedElement().getNodeName()
                        + " / Skipping." );
                    continue;
                }
                // We must be carefull: The refferringElement commonly points to
                // the original Document
                // but not to the newly created attackerDocument.
                // Thus we must use the findCorrespondingElement method.
                // TODO: I think this is not necessary for the init() Method.
                // Element refferingElement =
                // DomUtilities.findCorrespondingElement(payload.getSignedElement().getOwnerDocument(),
                // payload.getReferringElement().getElementNode());
                Element refferingElement = payload.getReferringElement().getElementNode();
                PayloadElement pay = new PayloadElement( payloadElement, refferingElement );
                SignedElement sig = new SignedElement( payload.getSignedElement(), refferingElement );
                XPathAnalyser xpa;
                xpa = new XPathAnalyser( payload.getReferringElement(), sig, pay, schemaAnalyser );
                // statistics
                if ( xpa.isFastXPath() )
                {
                    ++countElementsReferedByFastXPath;
                }
                else if ( xpa.isPrefixfreeTransformedFastXPath() )
                {
                    ++countElementsReferedByPrefixfreeTransformedFastXPath;
                }

                int possibilities = xpa.getMaxPossibilites();
                if ( possibilities > 0 )
                {
                    maxPossibilites = ( maxPossibilites == 0 ? possibilities : maxPossibilites * possibilities );
                    analyserList.add( xpa );
                    usedPayloads.add( payload );
                }
            }
            else
            {
                LOG.info( "No payload for " + payload.getSignedElement().getNodeName() + " detected / Skipping." );
            }
        }
        this.payloadList = usedPayloads;
    }

    public List<Payload> getUsedPayloads()
    {
        return payloadList;
    }

    public List<XPathAnalyser> getAnalyserList()
    {
        return analyserList;
    }

    public int getCountSignedElements()
    {
        return countSignedElements;
    }

    public int getCountElementsReferedByID()
    {
        return countElementsReferedByID;
    }

    public int getCountElementsReferedByXPath()
    {
        return countElementsReferedByXPath;
    }

    public int getCountElementsReferedByFastXPath()
    {
        return countElementsReferedByFastXPath;
    }

    public int getCountElementsReferedByPrefixfreeTransformedFastXPath()
    {
        return countElementsReferedByPrefixfreeTransformedFastXPath;
    }
}
