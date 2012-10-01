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
package wsattacker.plugin.signatureWrapping.xpath.parts;

import java.util.ArrayList;
import java.util.List;

import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathPartInterface;
import wsattacker.plugin.signatureWrapping.xpath.parts.axis.AxisSpecifier;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.Predicate;
import wsattacker.plugin.signatureWrapping.xpath.parts.util.XPathInspectorTools;

/**
 * A Step is a part of an XPath which is inside two slashes (except the first and last one). It consists o an
 * AxisSpecifier and a List of Predicates.
 */
public class Step implements XPathPartInterface
{
  private String          step;
  private Step            nextStep, previousStep;
  private AxisSpecifier   axisSpecifier;
  private List<Predicate> predicates;

  public Step(String relativeLocationPath)
  {
    this.step = relativeLocationPath;
    this.predicates = new ArrayList<Predicate>();
    this.nextStep = null;
    this.previousStep = null;
    eval();
  }

  public String getStep()
  {
    return step;
  }

  /**
   * Returns the previous Step or null if the current Step is the first Step
   * 
   * @return
   */
  public Step getPreviousStep()
  {
    return previousStep;
  }

  protected void setPreviousStep(Step previousStep)
  {
    this.previousStep = previousStep;
  }

  /**
   * Returns the next Step or null if current Step is the last Step
   * 
   * @return
   */
  public Step getNextStep()
  {
    return nextStep;
  }

  protected void setNextStep(Step nextStep)
  {
    this.nextStep = nextStep;
  }

  public void setPredicates(List<Predicate> predicates)
  {
    this.predicates = predicates;
  }

  public AxisSpecifier getAxisSpecifier()
  {
    return axisSpecifier;
  }

  public List<Predicate> getPredicates()
  {
    return predicates;
  }

  @Override
  public String toString()
  {
    return step;
  }

  @Override
  public String toFullString()
  {
    return axisSpecifier.toFullString() + XPathInspectorTools.implodeList(predicates, "", "[", "]");
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof String) {
		  return equals(new Step((String) o));
	  }
    if (o instanceof Step)
    {
      Step rel = (Step) o;
      return rel.getAxisSpecifier().equals(getAxisSpecifier()) && rel.getPredicates().equals(getPredicates());
    }
    return false;
  }

  /*
   * Evaluation Methods
   */

  private void eval()
  {

    int open = nextOpeningBrace(0);
    int close;
    if (open < 0)
    {
      axisSpecifier = new AxisSpecifier(step);
      return;
    }
    axisSpecifier = new AxisSpecifier(step.substring(0, open));

    while (open > 0)
    {
      close = nextClosingBrace(open + 1);
      String pred = step.substring(open + 1, close);
      predicates.add(new Predicate(pred));
      open = nextOpeningBrace(close + 1);
    }

  }

  private int nextOpeningBrace(int startIndex)
  {
    return XPathInspectorTools.nextChar(step, '[', startIndex);
  }

  private int nextClosingBrace(int startIndex)
  {
    return XPathInspectorTools.nextChar(step, ']', startIndex);
  }

  public String getPreXPath()
  {
    // build pre-xpath
    StringBuffer buf;
    Step it; // kind of iterator

    buf = new StringBuffer();
    it = getPreviousStep();
    while (it != null)
    {
      buf.insert(0, it.getStep()).insert(0, '/');
      it = it.getPreviousStep();
    }
    return buf.toString();
  }

  public String getPostXPath()
  {
    // build pre-xpath
    StringBuffer buf;
    Step it; // kind of iterator

    // build post-xpath
    buf = new StringBuffer();
    it = getNextStep();
    while (it != null)
    {
      buf.append('/').append(it.getStep());
      it = it.getNextStep();
    }
    if (buf.length() > 0) {
		  buf.deleteCharAt(0);
	  } // delete leading slash
    return buf.toString();
  }
}
