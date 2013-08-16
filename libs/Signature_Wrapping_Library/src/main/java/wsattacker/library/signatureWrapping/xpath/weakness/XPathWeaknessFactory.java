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
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.option.PayloadElement;
import wsattacker.library.signatureWrapping.option.SignedElement;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.util.signature.ReferenceElement;
import wsattacker.library.signatureWrapping.util.signature.XPathElement;
import wsattacker.library.signatureWrapping.xpath.interfaces.XPathWeaknessFactoryInterface;
import wsattacker.library.signatureWrapping.xpath.interfaces.XPathWeaknessInterface;
import wsattacker.library.signatureWrapping.xpath.parts.AbsoluteLocationPath;
import wsattacker.library.signatureWrapping.xpath.parts.Step;

/**
 * A concrete implementation of a WeaknessFactory.
 * Currently analyzes an XPath and searches for:
 * 1) DescendantWeakness
 * 2) AttributeWkeaness
 * 3) NamespaceInjectionWeakness
 */
public class XPathWeaknessFactory implements XPathWeaknessFactoryInterface {

    @Override
    public List<XPathWeaknessInterface> generate(AbsoluteLocationPath xpath,
      SignedElement signedElement,
      PayloadElement payloadElement,
      SchemaAnalyzer schemaAnalyser) {
        List<XPathWeaknessInterface> weaknessList = new ArrayList<XPathWeaknessInterface>();
        List<Step> steps = xpath.getRelativeLocationPaths();
        // CASE: ID-Reference + No manually set XPAth by user
        if (xpath.getReferringElement() instanceof ReferenceElement && xpath.getReferringElement().getXPath().equals(((ReferenceElement) xpath.getReferringElement()).transformIDtoXPath())) {
            try {
                // info: steps.get(0) is '//' due to transformIDtoXPath method
                XPathWeaknessInterface weakness = new XPathDescendantWeakness(steps.get(0), signedElement, payloadElement, schemaAnalyser);
                try {
                    XPathWeaknessInterface evelopedTransformation = new EnvelopedTransformationWeakness(weakness, signedElement);
                    weaknessList.add(evelopedTransformation);
                } catch (InvalidWeaknessException e) {
                    weaknessList.add(weakness);
                }

            } catch (InvalidWeaknessException e) {
                // Nothing to do
                // this should never happen
            }
            // Nothing else to do
            // could also be removed, as the for loop will do the same,
            // but could find additional weaknesses which are not usefull (e.g. XPathAttributeWeakness)
            return weaknessList;
        }
        for (int i = 0; i < steps.size(); ++i) {
            Step cur = steps.get(i);
            // XPathDescendantWeakness
            try {
                weaknessList.add(new XPathDescendantWeakness(cur, signedElement, payloadElement, schemaAnalyser));
            } catch (InvalidWeaknessException e) {
                // Nothing to do
            }
            // Add XPathAttribueWeakness
            try {
                weaknessList.add(new XPathAttributeWeakness(cur, signedElement, payloadElement));
            } catch (InvalidWeaknessException e) {
                // Nothing to do
            }
            // Add XPathNamespaceInjectionWeakness
            try {
                weaknessList.add(new XPathNamespaceInjectionWeakness((XPathElement) xpath.getReferringElement(), cur, signedElement, payloadElement));
            } catch (InvalidWeaknessException e) {
                // Nothing to do
            } catch (Exception e) {
                // in case that cast does not work, should never happen
            }

        }
        for (int i = 0; i < weaknessList.size(); ++i) {
            XPathWeaknessInterface weakness = weaknessList.get(i);
            try {
                XPathWeaknessInterface evelopedTransformation = new EnvelopedTransformationWeakness(weakness, signedElement);
                weaknessList.add(i, evelopedTransformation);
                weaknessList.remove(i + 1);
            } catch (InvalidWeaknessException e) {
                // nothing to do
            }
        }
        return weaknessList;
    }
}
