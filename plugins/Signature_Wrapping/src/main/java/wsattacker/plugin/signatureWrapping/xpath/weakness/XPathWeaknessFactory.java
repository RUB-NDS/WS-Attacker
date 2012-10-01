/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2011 Christian Mainka
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package wsattacker.plugin.signatureWrapping.xpath.weakness;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzerInterface;
import wsattacker.plugin.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.plugin.signatureWrapping.util.signature.ReferenceElement;
import wsattacker.plugin.signatureWrapping.util.signature.XPathElement;
import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathWeakness;
import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathWeaknessFactoryInterface;
import wsattacker.plugin.signatureWrapping.xpath.parts.AbsoluteLocationPath;
import wsattacker.plugin.signatureWrapping.xpath.parts.Step;

/**
 * A concrete implementation of a WeaknessFactory.
 * Currently analyzes an XPath and searches for:
 * 1) DescendantWeakness
 * 2) AttributeWkeaness
 * 3) NamespaceInjectionWeakness
 */
public class XPathWeaknessFactory implements XPathWeaknessFactoryInterface
{

  @Override
  public List<XPathWeakness> generate(AbsoluteLocationPath xpath,
                                      Element signedElement,
                                      Element payloadElement,
                                      SchemaAnalyzerInterface schemaAnalyser)
  {
    List<XPathWeakness> weaknesses = new ArrayList<XPathWeakness>();
    List<Step> steps = xpath.getRelativeLocationPaths();
    if (xpath.getReferringElement() instanceof ReferenceElement && xpath.getReferringElement().getXPath().equals(((ReferenceElement) xpath.getReferringElement()).transformIDtoXPath())) {
      try
      {
        weaknesses.add(new XPathDescendantWeakness(steps.get(0), signedElement.getOwnerDocument(), payloadElement, schemaAnalyser));
      }
      catch (InvalidWeaknessException e) {
        // Nothing to do
        // this should never happen
      }
      // Nothing else to do
      // could also be removed, as the for loop will do the same,
      // but could find additional weaknesses which are not usefull (e.g. XPathAttributeWeakness)
      return weaknesses;
    }
    for (int i = 0; i < steps.size(); ++i)
    {
      Step cur = steps.get(i);
      // XPathDescendantWeakness
      try
      {
        weaknesses.add(new XPathDescendantWeakness(cur, signedElement.getOwnerDocument(), payloadElement, schemaAnalyser));
      }
      catch (InvalidWeaknessException e) {
        // Nothing to do
      }
      // Add XPathAttribueWeakness
      try
      {
        weaknesses.add(new XPathAttributeWeakness(cur, signedElement, payloadElement));
      }
      catch (InvalidWeaknessException e) {
        // Nothing to do
      }
      // Add XPathNamespaceInjectionWeakness
      try
      {
        weaknesses.add(new XPathNamespaceInjectionWeakness((XPathElement) xpath.getReferringElement(), cur, signedElement, payloadElement));
      }
      catch (InvalidWeaknessException e) {
        // Nothing to do
      }
      catch (Exception e) {
        // in case that cast does not work, should never happen
      }

    }
    return weaknesses;
  }

}
