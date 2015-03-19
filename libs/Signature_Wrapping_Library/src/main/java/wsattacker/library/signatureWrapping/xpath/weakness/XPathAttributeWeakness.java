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
package wsattacker.library.signatureWrapping.xpath.weakness;

import java.util.*;
import org.w3c.dom.Element;
import wsattacker.library.signatureWrapping.option.PayloadElement;
import wsattacker.library.signatureWrapping.option.SignedElement;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.xpath.interfaces.XPathWeaknessInterface;
import wsattacker.library.signatureWrapping.xpath.parts.Step;
import wsattacker.library.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.library.signatureWrapping.xpath.weakness.util.XPathWeaknessTools;

/**
 * This Weakness is a Wrapper for the XPathAttributeWeaknessPostProcess. Unlike XPathDescendantWeakness, this Weakness
 * just clones the signed part and places it directly before or after this element. Afterwards, the
 * XPathAttributeWeaknessPostProcess is used to modify the attribute values.
 */
public class XPathAttributeWeakness
    implements XPathWeaknessInterface
{

    private final XPathWeaknessInterface postProcess;

    private final Step step;

    private final int matches;

    public XPathAttributeWeakness( Step step, SignedElement signedElement, PayloadElement payloadElement )
        throws InvalidWeaknessException
    {
        this.step = step;
        this.matches = XPathWeaknessTools.getSignedPostPart( step, signedElement.getSignedElement() ).size();
        this.postProcess = new XPathAttributeWeaknessPostProcess( step );
    }

    @Override
    public int getNumberOfPossibilities()
    {
        // *2 : Place Payload before and after Signed Element
        // *matches : If XPath matches multiple Elements
        // *postProcess.getNumberOfPossibilities() : self explaining
        return 2 * matches * postProcess.getNumberOfPossibilities();
    }

    /**
     * Simply detects the affected element and clones it before or after the signed element. Afterwards, the
     * XPathAttributeWeaknessPostProcess is called.
     */
    @Override
    public void abuseWeakness( int index, SignedElement signedElement, PayloadElement payloadElement )
        throws InvalidWeaknessException
    {
        boolean before = ( index % 2 ) == 0;
        index /= 2;
        int useMatch = index % matches;
        index /= matches;
        int abuseIndex = index % postProcess.getNumberOfPossibilities();

        List<Element> signedPostPartMatches =
            XPathWeaknessTools.getSignedPostPart( step, signedElement.getSignedElement() );
        if ( useMatch > signedPostPartMatches.size() )
        {
            throw new InvalidWeaknessException( "Could not find index " + useMatch + " in attribute XPath matches." );
        }
        Element signedPostPart = signedPostPartMatches.get( useMatch );
        // Use subfunction from XPathDescendantWeakness to create the payload
        Element payloadPostPart =
            XPathWeaknessTools.createPayloadPostPart( signedPostPart, signedElement.getSignedElement(),
                                                      payloadElement.getPayloadElement() );
        if ( before )
        {
            WeaknessLog.append( "Inserted Payload just before " + signedPostPart.getNodeName() );
            signedPostPart.getParentNode().insertBefore( payloadPostPart, signedPostPart );
        }
        else
        {
            WeaknessLog.append( "Inserted Payload after " + signedPostPart.getNodeName() );
            signedPostPart.getParentNode().appendChild( payloadPostPart );
        }
        // call post process
        postProcess.abuseWeakness( abuseIndex, signedElement, payloadElement );
    }

}
