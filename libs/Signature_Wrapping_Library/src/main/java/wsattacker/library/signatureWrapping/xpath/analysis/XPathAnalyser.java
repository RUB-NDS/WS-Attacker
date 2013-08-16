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
package wsattacker.library.signatureWrapping.xpath.analysis;

import java.util.*;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.option.PayloadElement;
import wsattacker.library.signatureWrapping.option.SignedElement;
import wsattacker.library.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.library.signatureWrapping.util.signature.ReferringElementInterface;
import wsattacker.library.signatureWrapping.xpath.interfaces.XPathWeaknessFactoryInterface;
import wsattacker.library.signatureWrapping.xpath.interfaces.XPathWeaknessInterface;
import wsattacker.library.signatureWrapping.xpath.parts.AbsoluteLocationPath;
import wsattacker.library.signatureWrapping.xpath.parts.Step;
import wsattacker.library.signatureWrapping.xpath.parts.predicate.AndExpression;
import wsattacker.library.signatureWrapping.xpath.parts.predicate.Predicate;
import wsattacker.library.signatureWrapping.xpath.parts.predicate.concrete.AttributeAndExpression;
import wsattacker.library.signatureWrapping.xpath.parts.predicate.concrete.LocalNameAndExpression;
import wsattacker.library.signatureWrapping.xpath.parts.predicate.concrete.NamespaceUriAndExpression;
import wsattacker.library.signatureWrapping.xpath.parts.predicate.concrete.PositionAndExpression;
import wsattacker.library.signatureWrapping.xpath.weakness.XPathWeaknessFactory;

/**
 * Analyzes an XPath expression.
 * Uses exactly one signed element and one payload element and relocates them
 * within the message.
 */
public class XPathAnalyser {

    public static XPathWeaknessFactoryInterface xpathWeaknessFactory = new XPathWeaknessFactory();
    private final AbsoluteLocationPath xpath;
    private final List<XPathWeaknessInterface> weaknesses;
    int maxPossibilites;

    /**
     * Constructor.
     *
     * @param ref            : Reference Element (Xpath, ID Reference)
     * @param signedElement  : the element which is signed
     * @param payloadElement : the payload element which shall replace the
     *                       signed element
     * @param schemaAnalyzer : instance of an SchemaAnaylzer
     */
    public XPathAnalyser(ReferringElementInterface ref,
      SignedElement signedElement,
      PayloadElement payloadElement,
      SchemaAnalyzer schemaAnalyzer) {
        this.xpath = new AbsoluteLocationPath(ref);
        this.weaknesses = xpathWeaknessFactory.generate(this.xpath, signedElement, payloadElement, schemaAnalyzer);
        // calculate number of possibilities
        maxPossibilites = 0;
        for (XPathWeaknessInterface w : weaknesses) {
            maxPossibilites += w.getNumberOfPossibilities();
        }
    }

    /**
     * String constructor should only be used for easy writing JUnit testes.
     *
     * @param xpath
     * @param signedElement
     * @param payloadElement
     * @param schemaAnalyser
     */
    public XPathAnalyser(String xpath,
      SignedElement signedElement,
      PayloadElement payloadElement,
      SchemaAnalyzer schemaAnalyser) {
        this.xpath = new AbsoluteLocationPath(xpath);
        this.weaknesses = xpathWeaknessFactory.generate(this.xpath, signedElement, payloadElement, schemaAnalyser);
        // calculate number of possibilities
        maxPossibilites = 0;
        for (XPathWeaknessInterface w : weaknesses) {
            maxPossibilites += w.getNumberOfPossibilities();
        }

    }

    /**
     * @return A List of XPathWeaknesses.
     */
    public List<XPathWeaknessInterface> getWeaknesses() {
        return weaknesses;
    }

    /**
     * @return The analyzed XPath expression.
     */
    public AbsoluteLocationPath getXPath() {
        return xpath;
    }

    /**
     * @return The total number of possible XSW messages.
     */
    public int getMaxPossibilites() {
        return maxPossibilites;
    }

    /**
     * Applies an XPath weakness. Both Elements are part of the same Document,
     * which will be modified.
     *
     * @param possibility
     *                       : Index of the weakness to abuse.
     * @param signedElement
     *                       : the signed element
     * @param payloadElement
     *                       : the payload element (must be in the same Document as the signed
     *                       element)
     *
     * @throws InvalidWeaknessException
     */
    public void abuseWeakness(int possibility,
      SignedElement signedElement,
      PayloadElement payloadElement)
      throws InvalidWeaknessException {
        if (possibility >= maxPossibilites) {
            return; // invalid possibility
        }
        for (int i = 0; i < weaknesses.size(); ++i) {
            XPathWeaknessInterface w = weaknesses.get(i);
            int num = w.getNumberOfPossibilities();
            if (possibility < num) {
                w.abuseWeakness(possibility, signedElement, payloadElement);
                return;
            }
            possibility -= num;
        }
    }

    /**
     * Validates if the given XPath follows the FastXPath grammar.
     * These are known to be fast and only vulnerable to namespace injection.
     *
     * @return
     */
    public boolean isFastXPath() {
        for (Step step : xpath.getRelativeLocationPaths()) {
            if (!step.getAxisSpecifier().getAxisName().toFullString().equals("child")) {
                return false;
            }
            if (step.getAxisSpecifier().getNodeType() != null) {
                return false;
            }
            if (step.getAxisSpecifier().getNodeName() == null) {
                return false;
            }
//      if (step.getAxisSpecifier().getNodeName().getPrefix().isEmpty())
//        return false;
            if (step.getAxisSpecifier().getNodeName().getNodeName().isEmpty()) {
                return false;
            }

            List<Predicate> predicates = step.getPredicates();
            if (predicates.isEmpty() || predicates.size() > 2) {
                return false;
            }
            int positions = 0;
            int attributes = 0;
            for (Predicate pred : step.getPredicates()) {
                if (pred.getOrExpressions().size() != 1) {
                    return false;
                }
                if (pred.getOrExpressions().get(0).getAndExpressions().size() != 1) {
                    return false;
                }
                AndExpression and = pred.getOrExpressions().get(0).getAndExpressions().get(0);
                if (and instanceof PositionAndExpression) {
                    ++positions;
                } else if (and instanceof AttributeAndExpression) {
                    ++attributes;
                }
            }
            if (positions > 1 || attributes > 1 || (attributes + positions) == 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validates if the given XPath follows the FastXPath grammar but without
     * prefixes.
     * This is known to be most secure.
     *
     * @return
     */
    public boolean isPrefixfreeTransformedFastXPath() {
        for (Step step : xpath.getRelativeLocationPaths()) {
            if (!step.getAxisSpecifier().getAxisName().toFullString().equals("child")) {
                return false;
            }
            if (step.getAxisSpecifier().getNodeName() != null) {
                return false;
            }
            if (step.getAxisSpecifier().getNodeType() == null) {
                return false;
            }
            if (!step.getAxisSpecifier().getNodeType().getNodeTypeName().equals("node")) {
                return false;
            }

            List<Predicate> predicates = step.getPredicates();
            if (predicates.isEmpty() || predicates.size() > 3) {
                return false;
            }
            int positions = 0;
            int attributes = 0;
            int ln = 0;
            int uri = 0;
            for (Predicate pred : step.getPredicates()) {
                if (pred.getOrExpressions().size() != 1) {
                    return false;
                }
                if (pred.getOrExpressions().get(0).getAndExpressions().size() != 1) {
                    List<AndExpression> andExpressions = pred.getOrExpressions().get(0).getAndExpressions();
                    if (andExpressions.size() > 2 || andExpressions.size() < 1) {
                        return false;
                    }
                    for (AndExpression and : andExpressions) {
                        if (and instanceof LocalNameAndExpression) {
                            ++ln;
                        } else if (and instanceof NamespaceUriAndExpression) {
                            ++uri;
                        }
                    }
                } else {
                    AndExpression and = pred.getOrExpressions().get(0).getAndExpressions().get(0);
                    if (and instanceof PositionAndExpression) {
                        ++positions;
                    } else if (and instanceof AttributeAndExpression) {
                        ++attributes;
                    }
                }
            }
            if (ln != 1 || uri != 1 || positions > 1 || attributes > 1 || (attributes + positions) == 0) {
                return false;
            }
        }
        return true;
    }
}
