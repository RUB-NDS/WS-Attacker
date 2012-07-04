package wsattacker.plugin.signatureWrapping.xpath.parts;

import java.util.ArrayList;
import java.util.List;

import wsattacker.plugin.signatureWrapping.util.signature.ReferringElementInterface;
import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathPartInterface;
import wsattacker.plugin.signatureWrapping.xpath.parts.util.XPathInspectorTools;

/**
 * An AbsoluteLocationPath is what is commonly called an XPath. It is mainly a container for Steps.
 */
public class AbsoluteLocationPath implements XPathPartInterface
{
  private String     absoluteLocationPath;
  private List<Step> relativeLocationPaths;
  private ReferringElementInterface referringElement = null;

  public AbsoluteLocationPath(ReferringElementInterface ref) {
    this(ref.getXPath());
    this.referringElement = ref;
  }
  public AbsoluteLocationPath(String absoluteLocationPath)
  {
    this.absoluteLocationPath = absoluteLocationPath;
    this.relativeLocationPaths = new ArrayList<Step>();
    eval();
  }

  public String getAbsoluteLocationPath()
  {
    return absoluteLocationPath;
  }

  public List<Step> getRelativeLocationPaths()
  {
    return relativeLocationPaths;
  }
  
  public ReferringElementInterface getReferringElement()
  {
    return referringElement;
  }

  @Override
  public String toString()
  {
    return absoluteLocationPath;
  }

  @Override
  public String toFullString()
  {
    return "/" + XPathInspectorTools.implodeList(relativeLocationPaths, "/");
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof String)
      return equals(new AbsoluteLocationPath((String) o));
    if (o instanceof AbsoluteLocationPath)
    {
      AbsoluteLocationPath abs = (AbsoluteLocationPath) o;
      return abs.getAbsoluteLocationPath().equals(getAbsoluteLocationPath());
    }
    return false;
  }

  /*
   * Evaluation Methods
   */

  private void eval()
  {
    int prev = 0, next;
    if (absoluteLocationPath.charAt(0) != '/')
      return; // not an absoluteLocationPath

    next = nextSlash(prev + 1);
    String relString;
    Step previousStep, currentStep;
    previousStep = null;
    while (next > 0)
    {
      relString = absoluteLocationPath.substring(prev + 1, next);
      // new current step
      currentStep = new Step(relString);

      if (previousStep != null)
      {
        // curent.prev = prev
        currentStep.setPreviousStep(previousStep);
        // prev.next = current
        previousStep.setNextStep(currentStep);
      }
      // add to list
      relativeLocationPaths.add(currentStep);
      // for next iteration: prev = current
      previousStep = currentStep;

      prev = next;
      next = nextSlash(prev + 1);
    }
    // Last Step = Rest of String
    relString = absoluteLocationPath.substring(prev + 1, absoluteLocationPath.length());
    currentStep = new Step(relString);

    if (previousStep != null)
    {
      // curent.prev = prev
      currentStep.setPreviousStep(previousStep);
      // prev.next = current
      previousStep.setNextStep(currentStep);
    }
    // add to list
    relativeLocationPaths.add(currentStep);
  }

  private int nextSlash(int startIndex)
  {
    return XPathInspectorTools.nextChar(absoluteLocationPath, '/', startIndex);
  }
}
