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
package wsattacker.plugin.signatureWrapping.test.singletests;

import static org.junit.Assert.*;
import static wsattacker.plugin.signatureWrapping.xpath.parts.util.XPathInspectorTools.*;

import java.util.List;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import wsattacker.plugin.signatureWrapping.util.exception.InvalidTypeException;
import wsattacker.plugin.signatureWrapping.xpath.parts.AbsoluteLocationPath;
import wsattacker.plugin.signatureWrapping.xpath.parts.Step;
import wsattacker.plugin.signatureWrapping.xpath.parts.axis.AxisSpecifier;
import wsattacker.plugin.signatureWrapping.xpath.parts.axis.NodeType;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.AndExpression;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.OrExpression;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.Predicate;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.concrete.AttributeAndExpression;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.concrete.LocalNameAndExpression;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.concrete.PositionAndExpression;
import wsattacker.plugin.signatureWrapping.xpath.parts.predicate.factory.FunctionAndExpression;

public class AxisAnalyserTest
{

  @BeforeClass
  public static void setUpBeforeClass()
                                       throws Exception
  {
  }

  @AfterClass
  public static void tearDownAfterClass()
                                         throws Exception
  {
  }

  @Before
  public void setUp()
                     throws Exception
  {
  }

  @After
  public void tearDown()
                        throws Exception
  {
  }

  @Test
  public void allInOneTest()
  {
    String xpath;
    xpath = "/soap:Envelope[1]/soap:Body[@id=\"foo\"][1]/axis:name";

    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
    assertEquals(xpath, abs.getAbsoluteLocationPath());

    List<Step> relList = abs.getRelativeLocationPaths();
    assertEquals(3, relList.size());

    Step rel;
    AxisSpecifier axis;

    // first
    rel = relList.get(0);
    assertEquals("soap:Envelope[1]", rel.getStep());

    assertNull("1) Previous Step should be null", rel.getPreviousStep());
    assertNotNull("1) Next step must be not null", rel.getNextStep());
    assertEquals("soap:Body[@id=\"foo\"][1]", rel.getNextStep().getStep());

    axis = rel.getAxisSpecifier();
    assertEquals("soap:Envelope", axis.getAxisSpecifier());

    // second
    rel = relList.get(1);
    assertEquals("soap:Body[@id=\"foo\"][1]", rel.getStep());
    assertNotNull("2) Previous Step must be not null", rel.getPreviousStep());
    assertEquals("soap:Envelope[1]", rel.getPreviousStep().getStep());
    assertNotNull("2) Next Step must be not null", rel.getNextStep());
    assertEquals("axis:name", rel.getNextStep().getStep());

    axis = rel.getAxisSpecifier();
    assertEquals("soap:Body", axis.getAxisSpecifier());

    // third = last
    rel = relList.get(2);
    assertEquals("axis:name", rel.getStep());
    assertNotNull("3) Previous Step must be not null", rel.getPreviousStep());
    assertEquals("soap:Body[@id=\"foo\"][1]", rel.getPreviousStep().getStep());
    assertNull("3) Next Step should be null", rel.getNextStep());

    axis = rel.getAxisSpecifier();
    assertEquals("axis:name", axis.getAxisSpecifier());
  }

  @Test
  public void preAndPostXPathTest()
  {
    String first = "soap:Envelope[1]";
    String second = "soap:Body[@id=\"foo\"][1]";
    String third = "axis:name";

    String xpath = String.format("/%s/%s/%s", first, second, third);

    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);

    Step step = abs.getRelativeLocationPaths().get(0);

    assertEquals("", step.getPreXPath());
    assertEquals(second + "/" + third, step.getPostXPath());

    step = step.getNextStep();

    assertEquals("/" + first, step.getPreXPath());
    assertEquals(third, step.getPostXPath());

    step = step.getNextStep();

    assertEquals("/" + first + "/" + second, step.getPreXPath());
    assertEquals("", step.getPostXPath());

  }

  @Test
  public void noPredicateTest()
  {
    String xpath = "/soap:Envelope[1]/soap:Body/axis:name[1]";
    AbsoluteLocationPath abs = new AbsoluteLocationPath(xpath);
    List<Step> relList = abs.getRelativeLocationPaths();
    assertEquals("Found: " + relList.toString(), 3, relList.size());
    assertEquals("soap:Envelope[1]", relList.get(0).getStep());
    assertEquals("soap:Body", relList.get(1).getStep());
    assertEquals("axis:name[1]", relList.get(2).getStep());
  }

  @Test
  public void predicateTest()
  {
    Step rel = new Step("soap:Body[@id=\"foo\"][1]");
    List<Predicate> predList = rel.getPredicates();
    assertEquals(2, predList.size());
    assertEquals("@id=\"foo\"", predList.get(0).getPredicate());
    assertEquals("1", predList.get(1).getPredicate());
  }

  @Test
  public void axisSpecifierTest()
  {
    AxisSpecifier ax;

    ax = new AxisSpecifier("localname");
    assertNotNull(ax.getNodeName());
    assertEquals("localname", ax.getNodeName().getLocalname());
    assertEquals("", ax.getNodeName().getPrefix());
    assertNotNull(ax.getAxisName());
    assertEquals("child", ax.getAxisName().toFullString());
    assertNull(ax.getNodeType());

    ax = new AxisSpecifier("prefix:localname");
    assertNotNull(ax.getNodeName());
    assertEquals("localname", ax.getNodeName().getLocalname());
    assertEquals("prefix", ax.getNodeName().getPrefix());
    assertNotNull(ax.getAxisName());
    assertEquals("child", ax.getAxisName().toFullString());
    assertNull(ax.getNodeType());;

    ax = new AxisSpecifier("child::prefix:localname");
    assertNotNull(ax.getNodeName());
    assertEquals("localname", ax.getNodeName().getLocalname());
    assertEquals("prefix", ax.getNodeName().getPrefix());
    assertNotNull(ax.getAxisName());
    assertEquals("child", ax.getAxisName().toFullString());
    assertNull(ax.getNodeType());;

    ax = new AxisSpecifier("decentant-or-self::prefix:localname");
    assertNotNull(ax.getNodeName());
    assertEquals("localname", ax.getNodeName().getLocalname());
    assertEquals("prefix", ax.getNodeName().getPrefix());
    assertNotNull(ax.getAxisName());
    assertEquals("decentant-or-self", ax.getAxisName().toFullString());
    assertNull(ax.getNodeType());;

    ax = new AxisSpecifier("@ns:attrname");
    assertNotNull(ax.getNodeName());
    assertEquals("attrname", ax.getNodeName().getLocalname());
    assertEquals("ns", ax.getNodeName().getPrefix());
    assertNotNull(ax.getAxisName());
    assertEquals("attribute", ax.getAxisName().toFullString());
    assertNull(ax.getNodeType());;

    ax = new AxisSpecifier("decendant::text()");
    assertNull(ax.getNodeName());
    assertNotNull(ax.getAxisName());
    assertEquals("decendant", ax.getAxisName().toFullString());
    assertNotNull(ax.getNodeType());;
    assertEquals("text()", ax.getNodeType().getNodeType());
    assertEquals("text", ax.getNodeType().getNodeTypeName());
    assertEquals("", ax.getNodeType().getNodeTypeArguments());

    ax = new AxisSpecifier("*");
    assertNull(ax.getNodeName());
    assertNotNull(ax.getAxisName());
    assertEquals("child", ax.getAxisName().toFullString());
    assertNotNull(ax.getNodeType());;
    assertEquals(new NodeType("*"), ax.getNodeType().getNodeType());
    assertEquals("node", ax.getNodeType().getNodeTypeName());
    assertEquals("", ax.getNodeType().getNodeTypeArguments());
  }

  @Test
  public void specialCases()
  {
    AbsoluteLocationPath abs = new AbsoluteLocationPath("//name");
    assertEquals("Rel: " + abs.getRelativeLocationPaths().toString(), 2, abs.getRelativeLocationPaths().size());
    assertEquals("", abs.getRelativeLocationPaths().get(0).getStep());
    assertEquals("name", abs.getRelativeLocationPaths().get(1).getStep());
    assertEquals("descendant-or-self", abs.getRelativeLocationPaths().get(0).getAxisSpecifier().getAxisName()
        .getAxisName());
    assertEquals("node", abs.getRelativeLocationPaths().get(0).getAxisSpecifier().getNodeType().getNodeTypeName());

    assertEquals(new Step("descendant-or-self::node()"), abs.getRelativeLocationPaths().get(0));
  }

  @Test
  public void toFullStringTest()
  {
    assertEquals("node()", (new NodeType("*")).toFullString());
    assertEquals("descendant-or-self::node()", (new Step("")).toFullString());
    assertEquals("self::node()", (new Step(".")).toFullString());
    assertEquals("parent::node()", (new Step("..")).toFullString());
    assertEquals("child::node()", (new Step("*")).toFullString());
    assertEquals("/child::foo:bar/child::blah", (new AbsoluteLocationPath("/foo:bar/blah")).toFullString());
    assertEquals("/descendant-or-self::node()/child::soap:body/child::node()[1]", (new AbsoluteLocationPath("//soap:body/*[1]"))
        .toFullString());
    assertEquals("/attribute::node()[1]", (new AbsoluteLocationPath("/@*[1]")).toFullString());
  }

  @Test
  public void nextStringTest()
  {
    assertEquals(5, nextString("to be or not to be", " or ", 0));
    assertEquals(4, nextString(" oro or not to be", " or ", 0));
    assertEquals(6, nextString("' or ' or not to be", " or ", 0));
    assertEquals(3, nextString("    or    ", " or ", 0));
  }

  @Test
  public void orExpressionsTest()
  {
    Predicate p;

    p = new Predicate("1");
    assertEquals(1, p.getOrExpressions().size());
    assertEquals(1, p.getOrExpressions().get(0).getAndExpressions().size());
    assertEquals("1", p.getOrExpressions().get(0).getAndExpressions().get(0).toString());

    p = new Predicate("1 and 2");
    assertEquals(1, p.getOrExpressions().size());
    assertEquals(2, p.getOrExpressions().get(0).getAndExpressions().size());
    assertEquals("1", p.getOrExpressions().get(0).getAndExpressions().get(0).toString());
    assertEquals("2", p.getOrExpressions().get(0).getAndExpressions().get(1).toString());

    p = new Predicate("1 and 2 or 3 and 4");
    assertEquals(2, p.getOrExpressions().size());
    assertEquals(2, p.getOrExpressions().get(0).getAndExpressions().size());
    assertEquals("1", p.getOrExpressions().get(0).getAndExpressions().get(0).toString());
    assertEquals("2", p.getOrExpressions().get(0).getAndExpressions().get(1).toString());
    assertEquals(2, p.getOrExpressions().get(1).getAndExpressions().size());
    assertEquals("3", p.getOrExpressions().get(1).getAndExpressions().get(0).toString());
    assertEquals("4", p.getOrExpressions().get(1).getAndExpressions().get(1).toString());

    p = new Predicate("  1   and      2   or    3     and    4   ");
    assertEquals(2, p.getOrExpressions().size());
    assertEquals(2, p.getOrExpressions().get(0).getAndExpressions().size());
    assertEquals("1", p.getOrExpressions().get(0).getAndExpressions().get(0).toString());
    assertEquals("2", p.getOrExpressions().get(0).getAndExpressions().get(1).toString());
    assertEquals(2, p.getOrExpressions().get(1).getAndExpressions().size());
    assertEquals("3", p.getOrExpressions().get(1).getAndExpressions().get(0).toString());
    assertEquals("4", p.getOrExpressions().get(1).getAndExpressions().get(1).toString());

    p = new Predicate("   @attr='here or there'     or    @attr='here and there'   ");
    assertEquals(2, p.getOrExpressions().size());
    assertEquals(1, p.getOrExpressions().get(0).getAndExpressions().size());
    assertEquals("@attr='here or there'", p.getOrExpressions().get(0).getAndExpressions().get(0).toString());
    assertEquals(1, p.getOrExpressions().get(1).getAndExpressions().size());
    assertEquals("@attr='here and there'", p.getOrExpressions().get(1).getAndExpressions().get(0).toString());
  }

  @Test
  public void orExpressionsWithAttributeAndExpressionsTest()
  {
    OrExpression or;
    String a1 = "1";
    String a2 = "@id='foo'";
    String a3 = "attribute::foo=\"bar\"";
    or = new OrExpression(String.format("%s and %s and %s", a1, a2, a3));
    List<AndExpression> ands = or.getAndExpressions();
    assertEquals(3, or.getAndExpressions().size());

    assertFalse(a1 + " is not an attribute", ands.get(0) instanceof AttributeAndExpression);
    assertTrue(a2 + " is an attribute", ands.get(1) instanceof AttributeAndExpression);
    assertTrue(a3 + " is an attribute", ands.get(2) instanceof AttributeAndExpression);
  }

  @Test
  public void attributeAndExpressionTest() throws InvalidTypeException
  {
    AttributeAndExpression and;

    // Common attributes

    and = new AttributeAndExpression("@id=\"foo\"");
    assertEquals("", and.getPrefix());
    assertEquals("id", and.getLocalname());
    assertEquals("foo", and.getValue());

    and = new AttributeAndExpression("@wsu:Id=\"foo\"");
    assertEquals("wsu", and.getPrefix());
    assertEquals("Id", and.getLocalname());
    assertEquals("foo", and.getValue());

    and = new AttributeAndExpression("attribute::id=\"foo\"");
    assertEquals("", and.getPrefix());
    assertEquals("id", and.getLocalname());
    assertEquals("foo", and.getValue());

    and = new AttributeAndExpression("attribute::wsu:Id=\"foo\"");
    assertEquals("wsu", and.getPrefix());
    assertEquals("Id", and.getLocalname());
    assertEquals("foo", and.getValue());

    and = new AttributeAndExpression("@id='foo'");
    assertEquals("", and.getPrefix());
    assertEquals("id", and.getLocalname());
    assertEquals("foo", and.getValue());

    and = new AttributeAndExpression("@wsu:Id='foo'");
    assertEquals("wsu", and.getPrefix());
    assertEquals("Id", and.getLocalname());
    assertEquals("foo", and.getValue());

    and = new AttributeAndExpression("attribute::id='foo'");
    assertEquals("", and.getPrefix());
    assertEquals("id", and.getLocalname());
    assertEquals("foo", and.getValue());

    and = new AttributeAndExpression("attribute::wsu:Id='foo'");
    assertEquals("wsu", and.getPrefix());
    assertEquals("Id", and.getLocalname());
    assertEquals("foo", and.getValue());

    // Special

    and = new AttributeAndExpression("@xyz=''");
    assertEquals("", and.getPrefix());
    assertEquals("xyz", and.getLocalname());
    assertEquals("", and.getValue());

    and = new AttributeAndExpression("@a='b'");
    assertEquals("", and.getPrefix());
    assertEquals("a", and.getLocalname());
    assertEquals("b", and.getValue());

    and = new AttributeAndExpression("@x:a='b'");
    assertEquals("x", and.getPrefix());
    assertEquals("a", and.getLocalname());
    assertEquals("b", and.getValue());
  }
  


  @Test
  public void positionAndExpressionTest() throws InvalidTypeException
  {
    PositionAndExpression and;
    
    and = new PositionAndExpression("1");
    assertTrue(and.getFunction().isEmpty());
    assertTrue(and.isSimpleIndex());
    assertEquals(1, and.getPosition());
    
    and = new PositionAndExpression("position()=1");
    assertEquals("position()", and.getFunction());
    assertTrue(and.isSimpleIndex());
    assertEquals(1, and.getPosition());
    
    and = new PositionAndExpression("position()=last()");
    assertEquals("position()", and.getFunction());
    assertEquals("last()", and.getPositonFunction());
    assertFalse(and.isSimpleIndex());
    assertEquals(-1, and.getPosition());
    
    and = new PositionAndExpression("position()=last()-3");
    assertEquals("position()", and.getFunction());
    assertEquals("last()-3", and.getPositonFunction());
    assertFalse(and.isSimpleIndex());
    assertEquals(-1, and.getPosition());

    
    and = new PositionAndExpression("last()-3");
    assertTrue(and.getFunction().isEmpty());
    assertEquals("last()-3", and.getPositonFunction());
    assertFalse(and.isSimpleIndex());
    assertEquals(-1, and.getPosition());
  }

  @Test (expected=InvalidTypeException.class)
  public void positionAndExpressionBadPositionTest() throws InvalidTypeException
  {
    new PositionAndExpression("0");
  }
  
  @Test
  public void functionAndExpressionBadPositionTest() throws InvalidTypeException
  {
    FunctionAndExpression and;
    
    and = new LocalNameAndExpression("local-name()='test'");
    assertEquals("local-name()", and.getFunctionName());
    assertEquals("test", and.getValue());

    and = new LocalNameAndExpression("local-name()=\"test\"");
    assertEquals("local-name()", and.getFunctionName());
    assertEquals("test", and.getValue());
  }

  @Test (expected=InvalidTypeException.class)
  public void functionAndExpressionBadQuoteTest() throws InvalidTypeException
  {
      new LocalNameAndExpression("local-name()=\"test'");
  }
  
}
